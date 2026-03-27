package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/samsung-sds/boanclaw/boan-credential-filter/internal/filter"
	"github.com/samsung-sds/boanclaw/boan-credential-filter/internal/kms"
)

func main() {
	listen := env("BOAN_LISTEN", ":8082")
	keyPath := env("BOAN_KMS_KEY", "/etc/boan-cred/aes.key")
	os.MkdirAll("/etc/boan-cred", 0700)

	enc, err := kms.New(keyPath)
	if err != nil {
		log.Fatalf("kms init: %v", err)
	}

	store := filter.NewStore(enc)

	mux := http.NewServeMux()

	mux.HandleFunc("/credential/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/credential/"), "/")

		switch {
		case len(parts) == 2 && parts[1] != "" && r.Method == http.MethodGet:
			resp, err := store.Get(parts[0], parts[1])
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)

		case len(parts) == 1 && parts[0] != "" && r.Method == http.MethodPost:
			var req filter.RegisterRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := store.Register(parts[0], &req); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusCreated)

		case len(parts) == 2 && parts[1] != "" && r.Method == http.MethodDelete:
			if store.Revoke(parts[0], parts[1]) {
				w.WriteHeader(http.StatusNoContent)
			} else {
				http.NotFound(w, r)
			}

		default:
			http.NotFound(w, r)
		}
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})

	log.Printf("boan-credential-filter listening on %s", listen)
	log.Fatal(http.ListenAndServe(listen, mux))
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
