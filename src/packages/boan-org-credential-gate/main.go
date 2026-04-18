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
	if jwtRequired {
		log.Printf("device-JWT gate ENABLED: %d trusted pubkey(s)", len(allowedPubs))
	} else {
		log.Printf("device-JWT gate DISABLED (bearer-only). Set BOAN_DEVICE_PUBKEYS to enable.")
	}

	mux := http.NewServeMux()

	// POST /v1/credentials/{org_id}   body: {role, key}
	// GET  /v1/credentials/{org_id}                    → list metadata
	// GET  /v1/credentials/{org_id}/{role}             → metadata only (no plaintext)
	// DELETE /v1/credentials/{org_id}/{role}
	mux.HandleFunc("/v1/credentials/", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(r, authToken) {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if jwtRequired && !verifyDeviceJWT(r, allowedPubs) {
			writeErr(w, http.StatusUnauthorized, "device JWT required")
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/credentials/"), "/")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		// strip trailing empty segment from trailing slash
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
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusCreated, registerResponse{
				Role: md.Role, OrgID: md.OrgID, Status: "ok",
				CreatedAt: md.CreatedAt, UpdatedAt: md.UpdatedAt,
			})

		case r.Method == http.MethodDelete && len(parts) == 2:
			if err := st.Delete(r.Context(), parts[0], parts[1]); err != nil {
				if errors.Is(err, store.ErrNotFound) {
					writeErr(w, http.StatusNotFound, "not found")
					return
				}
				writeErr(w, http.StatusInternalServerError, err.Error())
				return
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			writeErr(w, http.StatusNotFound, "not found")
		}
	})

	// POST /v1/resolve  body: {org_id, role, caller_id, target_host}
	// Returns plaintext. Logs the caller + target for audit. Plaintext never
	// persisted. Intended caller: org-llm-proxy only.
	mux.HandleFunc("/v1/resolve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		if !authOK(r, authToken) {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if jwtRequired && !verifyDeviceJWT(r, allowedPubs) {
			writeErr(w, http.StatusUnauthorized, "device JWT required")
			return
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
				writeErr(w, http.StatusNotFound, "credential not found")
				return
			}
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		log.Printf("resolve ok org=%s role=%s caller=%s target=%s", req.OrgID, req.Role, req.CallerID, req.TargetHost)
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
	jwt := strings.TrimSpace(r.Header.Get("X-Boan-Device-JWT"))
	if jwt == "" {
		return false
	}
	claims, err := devicejwt.Verify(jwt, allowed, deviceJWTAudience, 60*time.Second)
	if err != nil {
		log.Printf("device JWT verify failed: %v", err)
		return false
	}
	if sub, ok := claims["sub"].(string); ok && sub != "" {
		r.Header.Set("X-Boan-Verified-Device", sub)
	}
	return true
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
