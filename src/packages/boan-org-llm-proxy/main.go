package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-org-llm-proxy/internal/auditlog"
	"github.com/samsung-sds/boanclaw/boan-org-llm-proxy/internal/credresolver"
	"github.com/samsung-sds/boanclaw/boan-org-llm-proxy/internal/devicejwt"
	"github.com/samsung-sds/boanclaw/boan-org-llm-proxy/internal/forwarder"
	"github.com/samsung-sds/boanclaw/boan-org-llm-proxy/internal/ratelimit"
)

const deviceJWTAudience = "boan-org-cloud"

func main() {
	auditlog.SetService("boan-org-llm-proxy")

	listen := env("BOAN_LISTEN", ":8091")
	authToken := strings.TrimSpace(os.Getenv("BOAN_ORG_LLM_PROXY_AUTH_TOKEN"))
	if authToken == "" {
		log.Fatal("BOAN_ORG_LLM_PROXY_AUTH_TOKEN is required")
	}

	allowed := splitCSV(env("BOAN_ORG_LLM_PROXY_ALLOWED_HOSTS", "ollama.com,api.anthropic.com,api.openai.com,generativelanguage.googleapis.com"))
	deny := splitCSV(env("BOAN_ORG_LLM_PROXY_DENY_HOSTS", "169.254.169.254,metadata.google.internal,localhost,127.0.0.1"))

	defaultTimeout := envDuration("BOAN_ORG_LLM_PROXY_DEFAULT_TIMEOUT_MS", 180000) * time.Millisecond
	maxTimeout := envDuration("BOAN_ORG_LLM_PROXY_MAX_TIMEOUT_MS", 600000) * time.Millisecond

	var resolver *credresolver.Resolver
	gateURL := strings.TrimSpace(os.Getenv("BOAN_ORG_CREDENTIAL_GATE_URL"))
	gateToken := strings.TrimSpace(os.Getenv("BOAN_ORG_CREDENTIAL_GATE_AUTH_TOKEN"))
	if gateURL != "" && gateToken != "" {
		resolver = credresolver.New(gateURL, gateToken)
		log.Printf("credential-gate resolver enabled: %s", gateURL)
		go func() {
			tick := time.NewTicker(60 * time.Second)
			defer tick.Stop()
			for range tick.C {
				resolver.Prune()
			}
		}()
	} else {
		log.Printf("credential-gate resolver DISABLED (no BOAN_ORG_CREDENTIAL_GATE_URL/TOKEN set)")
	}

	fwd := forwarder.New(allowed, deny, defaultTimeout, maxTimeout, resolver)

	allowedPubs, err := devicejwt.ParseAllowedPubs(os.Getenv("BOAN_DEVICE_PUBKEYS"))
	if err != nil {
		log.Fatalf("BOAN_DEVICE_PUBKEYS parse: %v", err)
	}
	jwtRequired := len(allowedPubs) > 0

	revoked := parseRevokedSet(os.Getenv("BOAN_REVOKED_DEVICES"))

	// Per-device rate limit: default 120 req/min per device.
	rpm := envInt("BOAN_ORG_LLM_PROXY_RPM", 120)
	limiter := ratelimit.New(rpm, time.Minute)
	go func() {
		tick := time.NewTicker(5 * time.Minute)
		defer tick.Stop()
		for range tick.C {
			limiter.Prune()
		}
	}()

	log.Printf("init: jwt=%v revoked_devices=%d rpm=%d", jwtRequired, len(revoked), rpm)

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/forward", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if r.Method != http.MethodPost {
			forwarder.EncodeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !authOK(r, authToken) {
			auditlog.Emit(auditlog.Event{EventType: "auth_reject", Severity: "WARNING", Reason: "bearer missing/invalid", Status: 401})
			forwarder.EncodeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var deviceID string
		if jwtRequired {
			jwt := strings.TrimSpace(r.Header.Get("X-Boan-Device-JWT"))
			if jwt == "" {
				auditlog.Emit(auditlog.Event{EventType: "auth_reject", Severity: "WARNING", Reason: "device JWT missing", Status: 401})
				forwarder.EncodeError(w, http.StatusUnauthorized, "device JWT required")
				return
			}
			claims, err := devicejwt.Verify(jwt, allowedPubs, deviceJWTAudience, 60*time.Second)
			if err != nil {
				auditlog.Emit(auditlog.Event{EventType: "auth_reject", Severity: "WARNING", Reason: "device JWT invalid: " + err.Error(), Status: 401})
				forwarder.EncodeError(w, http.StatusUnauthorized, "device JWT invalid: "+err.Error())
				return
			}
			if sub, ok := claims["sub"].(string); ok {
				deviceID = sub
				r.Header.Set("X-Boan-Verified-Device", sub)
			}
			if _, blocked := revoked[deviceID]; blocked {
				auditlog.Emit(auditlog.Event{EventType: "auth_reject", Severity: "WARNING", Reason: "device revoked", Status: 403, DeviceID: deviceID})
				forwarder.EncodeError(w, http.StatusForbidden, "device revoked")
				return
			}
		}

		if !limiter.Allow(rateKey(deviceID, r)) {
			auditlog.Emit(auditlog.Event{EventType: "rate_limit", Severity: "WARNING", Reason: "per-device rpm exceeded", Status: 429, DeviceID: deviceID})
			forwarder.EncodeError(w, http.StatusTooManyRequests, "rate limit exceeded (per device)")
			return
		}

		var req forwarder.ForwardRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			forwarder.EncodeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
		resp, err := fwd.Forward(r.Context(), &req)
		if err != nil {
			auditlog.Emit(auditlog.Event{
				EventType: "forward_error", Severity: "ERROR",
				OrgID: req.OrgID, DeviceID: deviceID, CallerID: req.CallerID,
				TargetHost: hostOf(req.Target), Reason: err.Error(),
				DurationMs: time.Since(start).Milliseconds(),
			})
			forwarder.EncodeError(w, http.StatusBadGateway, err.Error())
			return
		}

		// body_bytes = 원본 바이트 수 (base64 decode)
		bytesOut := 0
		if len(resp.BodyB64) > 0 {
			bytesOut = (len(resp.BodyB64) * 3) / 4
		}
		auditlog.Emit(auditlog.Event{
			EventType:  "forward_ok",
			OrgID:      req.OrgID,
			DeviceID:   deviceID,
			CallerID:   req.CallerID,
			TargetHost: hostOf(req.Target),
			Status:     resp.Status,
			Bytes:      bytesOut,
			DurationMs: time.Since(start).Milliseconds(),
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
		WriteTimeout:      0,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("boan-org-llm-proxy listening on %s (allowed=%v deny=%v)", listen, allowed, deny)
	log.Fatal(srv.ListenAndServe())
}

func rateKey(deviceID string, r *http.Request) string {
	if deviceID != "" {
		return "dev:" + deviceID
	}
	// Fall back to client IP when no device — still prevents runaway loops.
	return "ip:" + clientIP(r)
}

func clientIP(r *http.Request) string {
	if h := r.Header.Get("X-Forwarded-For"); h != "" {
		if idx := strings.IndexByte(h, ','); idx >= 0 {
			return strings.TrimSpace(h[:idx])
		}
		return strings.TrimSpace(h)
	}
	return r.RemoteAddr
}

func parseRevokedSet(csv string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out[p] = struct{}{}
		}
	}
	return out
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u == nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// Silence unused imports during incremental edits.
var _ = base64.StdEncoding

func authOK(r *http.Request, expected string) bool {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if h == "" {
		return false
	}
	prefix := "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	return subtle.ConstantTimeCompare([]byte(tok), []byte(expected)) == 1
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallbackMs int) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return time.Duration(fallbackMs)
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return time.Duration(fallbackMs)
	}
	return time.Duration(n)
}

func envInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

func splitCSV(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
