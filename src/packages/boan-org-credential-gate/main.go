package main

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-org-credential-gate/internal/auditlog"
	"github.com/samsung-sds/boanclaw/boan-org-credential-gate/internal/devicejwt"
	"github.com/samsung-sds/boanclaw/boan-org-credential-gate/internal/store"
)

const deviceJWTAudience = "boan-org-cloud"

type registerRequest struct {
	Role      string `json:"role"`
	Key       string `json:"key"`
	TTLHours  int    `json:"ttl_hours,omitempty"`
}

type registerResponse struct {
	Role      string    `json:"role"`
	OrgID     string    `json:"org_id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type resolveRequest struct {
	OrgID      string `json:"org_id"`
	Role       string `json:"role"`
	CallerID   string `json:"caller_id,omitempty"`
	TargetHost string `json:"target_host,omitempty"`
}

type resolveResponse struct {
	Plaintext string `json:"plaintext"`
}

func main() {
	auditlog.SetService("boan-org-credential-gate")

	listen := env("BOAN_LISTEN", ":8092")
	projectID := env("BOAN_GCP_PROJECT_ID", "")
	if projectID == "" {
		log.Fatal("BOAN_GCP_PROJECT_ID is required")
	}
	authToken := strings.TrimSpace(os.Getenv("BOAN_ORG_CREDENTIAL_GATE_AUTH_TOKEN"))
	if authToken == "" {
		log.Fatal("BOAN_ORG_CREDENTIAL_GATE_AUTH_TOKEN is required")
	}

	ctx := context.Background()
	st, err := store.New(ctx, projectID)
	if err != nil {
		log.Fatalf("store init: %v", err)
	}
	defer st.Close()

	allowedPubs, err := devicejwt.ParseAllowedPubs(os.Getenv("BOAN_DEVICE_PUBKEYS"))
	if err != nil {
		log.Fatalf("BOAN_DEVICE_PUBKEYS parse: %v", err)
	}
	jwtRequired := len(allowedPubs) > 0
	revoked := parseRevokedSet(os.Getenv("BOAN_REVOKED_DEVICES"))
	log.Printf("init: jwt=%v revoked_devices=%d", jwtRequired, len(revoked))

	mux := http.NewServeMux()

	// POST /v1/credentials/{org_id}   body: {role, key}
	// GET  /v1/credentials/{org_id}                    → list metadata
	// GET  /v1/credentials/{org_id}/{role}             → metadata only (no plaintext)
	// DELETE /v1/credentials/{org_id}/{role}
	mux.HandleFunc("/v1/credentials/", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(r, authToken) {
			auditlog.Emit(auditlog.Event{EventType: "auth_reject", Severity: "WARNING", Reason: "bearer missing/invalid", Status: 401})
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		deviceID := ""
		if jwtRequired {
			ok, id := verifyAndExtract(r, allowedPubs)
			if !ok {
				auditlog.Emit(auditlog.Event{EventType: "auth_reject", Severity: "WARNING", Reason: "device JWT", Status: 401})
				writeErr(w, http.StatusUnauthorized, "device JWT required")
				return
			}
			deviceID = id
			if _, blocked := revoked[deviceID]; blocked {
				auditlog.Emit(auditlog.Event{EventType: "auth_reject", Severity: "WARNING", Reason: "device revoked", Status: 403, DeviceID: deviceID})
				writeErr(w, http.StatusForbidden, "device revoked")
				return
			}
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/credentials/"), "/")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		if len(parts) > 0 && parts[len(parts)-1] == "" {
			parts = parts[:len(parts)-1]
		}

		switch {
		case r.Method == http.MethodGet && len(parts) == 1:
			list, err := st.List(r.Context(), parts[0])
			if err != nil {
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			auditlog.Emit(auditlog.Event{EventType: "credential_list", OrgID: parts[0], DeviceID: deviceID, Status: 200, Bytes: len(list)})
			writeJSON(w, http.StatusOK, list)

		case r.Method == http.MethodGet && len(parts) == 2:
			md, err := st.Head(r.Context(), parts[0], parts[1])
			if err != nil {
				if errors.Is(err, store.ErrNotFound) {
					writeErr(w, http.StatusNotFound, "not found")
					return
				}
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			auditlog.Emit(auditlog.Event{EventType: "credential_head", OrgID: parts[0], Role: parts[1], DeviceID: deviceID, Status: 200})
			writeJSON(w, http.StatusOK, md)

		case r.Method == http.MethodPost && len(parts) == 1:
			var req registerRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
				return
			}
			if strings.TrimSpace(req.Role) == "" || req.Key == "" {
				writeErr(w, http.StatusBadRequest, "role and key are required")
				return
			}
			md, err := st.Put(r.Context(), parts[0], req.Role, req.Key)
			if err != nil {
				auditlog.Emit(auditlog.Event{EventType: "credential_put_error", Severity: "ERROR", OrgID: parts[0], Role: req.Role, DeviceID: deviceID, Reason: err.Error()})
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			auditlog.Emit(auditlog.Event{EventType: "credential_put", OrgID: md.OrgID, Role: md.Role, DeviceID: deviceID, Status: 201})
			writeJSON(w, http.StatusCreated, registerResponse{
				Role: md.Role, OrgID: md.OrgID, Status: "ok",
				CreatedAt: md.CreatedAt, UpdatedAt: md.UpdatedAt,
			})

		case r.Method == http.MethodPost && len(parts) == 3 && parts[2] == "revoke":
			// POST /v1/credentials/{org}/{role}/revoke
			if err := st.Delete(r.Context(), parts[0], parts[1]); err != nil && !errors.Is(err, store.ErrNotFound) {
				auditlog.Emit(auditlog.Event{EventType: "credential_revoke_error", Severity: "ERROR", OrgID: parts[0], Role: parts[1], DeviceID: deviceID, Reason: err.Error()})
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			auditlog.Emit(auditlog.Event{EventType: "credential_revoke", Severity: "NOTICE", OrgID: parts[0], Role: parts[1], DeviceID: deviceID, Status: 200})
			writeJSON(w, http.StatusOK, map[string]any{"org_id": parts[0], "role": parts[1], "revoked": true, "ts": time.Now().UTC().Format(time.RFC3339)})

		case r.Method == http.MethodDelete && len(parts) == 2:
			if err := st.Delete(r.Context(), parts[0], parts[1]); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					writeErr(w, http.StatusNotFound, "not found")
					return
				}
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			auditlog.Emit(auditlog.Event{EventType: "credential_delete", OrgID: parts[0], Role: parts[1], DeviceID: deviceID, Status: 204})
			w.WriteHeader(http.StatusNoContent)

		default:
			writeErr(w, http.StatusNotFound, "not found")
		}
	})

	// POST /v1/resolve  body: {org_id, role, caller_id, target_host}
	// Returns plaintext. Logs the caller + target for audit. Plaintext never
	// persisted. Intended caller: org-llm-proxy only.
	mux.HandleFunc("/v1/resolve", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !authOK(r, authToken) {
			auditlog.Emit(auditlog.Event{EventType: "auth_reject", Severity: "WARNING", Reason: "bearer missing/invalid", Status: 401})
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		deviceID := ""
		if jwtRequired {
			ok, id := verifyAndExtract(r, allowedPubs)
			if !ok {
				auditlog.Emit(auditlog.Event{EventType: "auth_reject", Severity: "WARNING", Reason: "device JWT", Status: 401})
				writeErr(w, http.StatusUnauthorized, "device JWT required")
				return
			}
			deviceID = id
			if _, blocked := revoked[deviceID]; blocked {
				auditlog.Emit(auditlog.Event{EventType: "auth_reject", Severity: "WARNING", Reason: "device revoked", Status: 403, DeviceID: deviceID})
				writeErr(w, http.StatusForbidden, "device revoked")
				return
			}
		}
		var req resolveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
			return
		}
		if strings.TrimSpace(req.OrgID) == "" || strings.TrimSpace(req.Role) == "" {
			writeErr(w, http.StatusBadRequest, "org_id and role are required")
			return
		}
		plaintext, err := st.Get(r.Context(), req.OrgID, req.Role)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				auditlog.Emit(auditlog.Event{EventType: "resolve_not_found", Severity: "WARNING", OrgID: req.OrgID, Role: req.Role, CallerID: req.CallerID, TargetHost: req.TargetHost, DeviceID: deviceID, Status: 404})
				writeErr(w, http.StatusNotFound, "credential not found")
				return
			}
			auditlog.Emit(auditlog.Event{EventType: "resolve_error", Severity: "ERROR", OrgID: req.OrgID, Role: req.Role, CallerID: req.CallerID, TargetHost: req.TargetHost, DeviceID: deviceID, Reason: err.Error()})
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		auditlog.Emit(auditlog.Event{
			EventType: "resolve_ok",
			OrgID:     req.OrgID, Role: req.Role,
			CallerID: req.CallerID, TargetHost: req.TargetHost,
			DeviceID: deviceID, Status: 200,
			DurationMs: time.Since(start).Milliseconds(),
		})
		writeJSON(w, http.StatusOK, resolveResponse{Plaintext: plaintext})
	})

	mux.HandleFunc("/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
	}
	log.Printf("boan-org-credential-gate listening on %s (project=%s)", listen, projectID)
	log.Fatal(srv.ListenAndServe())
}

func authOK(r *http.Request, expected string) bool {
	h := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(h, "Bearer ") {
		return false
	}
	tok := strings.TrimSpace(h[len("Bearer "):])
	return subtle.ConstantTimeCompare([]byte(tok), []byte(expected)) == 1
}

func verifyDeviceJWT(r *http.Request, allowed []ed25519.PublicKey) bool {
	ok, _ := verifyAndExtract(r, allowed)
	return ok
}

// verifyAndExtract validates the JWT and returns (true, device_id) on success.
func verifyAndExtract(r *http.Request, allowed []ed25519.PublicKey) (bool, string) {
	jwt := strings.TrimSpace(r.Header.Get("X-Boan-Device-JWT"))
	if jwt == "" {
		return false, ""
	}
	claims, err := devicejwt.Verify(jwt, allowed, deviceJWTAudience, 60*time.Second)
	if err != nil {
		log.Printf("device JWT verify failed: %v", err)
		return false, ""
	}
	sub, _ := claims["sub"].(string)
	if sub != "" {
		r.Header.Set("X-Boan-Verified-Device", sub)
	}
	return true, sub
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

func writeErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
