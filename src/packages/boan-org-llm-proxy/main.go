package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-org-llm-proxy/internal/forwarder"
)

func main() {
	listen := env("BOAN_LISTEN", ":8091")
	authToken := strings.TrimSpace(os.Getenv("BOAN_ORG_LLM_PROXY_AUTH_TOKEN"))
	if authToken == "" {
		log.Fatal("BOAN_ORG_LLM_PROXY_AUTH_TOKEN is required")
	}

	allowed := splitCSV(env("BOAN_ORG_LLM_PROXY_ALLOWED_HOSTS", "ollama.com,api.anthropic.com,api.openai.com,generativelanguage.googleapis.com"))
	deny := splitCSV(env("BOAN_ORG_LLM_PROXY_DENY_HOSTS", "169.254.169.254,metadata.google.internal,localhost,127.0.0.1"))

	defaultTimeout := envDuration("BOAN_ORG_LLM_PROXY_DEFAULT_TIMEOUT_MS", 180000) * time.Millisecond
	maxTimeout := envDuration("BOAN_ORG_LLM_PROXY_MAX_TIMEOUT_MS", 600000) * time.Millisecond

	fwd := forwarder.New(allowed, deny, defaultTimeout, maxTimeout)

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/forward", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			forwarder.EncodeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !authOK(r, authToken) {
			forwarder.EncodeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		var req forwarder.ForwardRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			forwarder.EncodeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
		resp, err := fwd.Forward(r.Context(), &req)
		if err != nil {
			log.Printf("forward failed target=%s err=%v", req.Target, err)
			forwarder.EncodeError(w, http.StatusBadGateway, err.Error())
			return
		}
		log.Printf("forward ok target=%s status=%d body_bytes=%d", req.Target, resp.Status, len(resp.BodyB64))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
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
