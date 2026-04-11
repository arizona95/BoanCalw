package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/samsung-sds/boanclaw/boan-llm-registry/internal/registry"
)

func main() {
	dataDir := env("BOAN_DATA_DIR", "/data/registry")
	reg := registry.New(dataDir)
	listen := env("BOAN_LISTEN", ":8081")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go reg.StartHealthCheck(ctx, 30*time.Second)

	mux := http.NewServeMux()

	mux.HandleFunc("/llm/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var obj registry.LLMObject
		if err := json.NewDecoder(r.Body).Decode(&obj); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := reg.Register(&obj); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(obj)
	})

	mux.HandleFunc("/llm/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(reg.List())
	})

	mux.HandleFunc("/llm/history", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(reg.History())
		case http.MethodDelete:
			// DELETE /llm/history — clear all history
			reg.ClearHistory()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/llm/history/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// DELETE /llm/history/{name}/{registeredAt}
		path := strings.TrimPrefix(r.URL.Path, "/llm/history/")
		idx := strings.Index(path, "/")
		if idx < 0 {
			http.Error(w, "missing registeredAt", http.StatusBadRequest)
			return
		}
		name := path[:idx]
		registeredAt := path[idx+1:]
		if reg.DeleteHistory(name, registeredAt) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "name": name})
		} else {
			http.NotFound(w, r)
		}
	})

	mux.HandleFunc("/llm/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/llm/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			http.NotFound(w, r)
			return
		}
		name := parts[0]

		switch {
		case len(parts) == 1 && r.Method == http.MethodDelete:
			if reg.Delete(name) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]string{"status": "deleted", "name": name})
			} else {
				http.NotFound(w, r)
			}
		case len(parts) == 2 && parts[1] == "bind-security" && r.Method == http.MethodPost:
			if err := reg.SetSecurityLLM(name); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "bound", "name": name})
		case len(parts) == 2 && parts[1] == "bind-security-lmm" && r.Method == http.MethodPost:
			if err := reg.SetSecurityLMM(name); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "bound-lmm", "name": name})
		case len(parts) == 3 && parts[1] == "bind-role" && r.Method == http.MethodPost:
			role := parts[2]
			if err := reg.BindRole(name, role); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "bound", "name": name, "role": role})
		case len(parts) == 3 && parts[1] == "unbind-role" && r.Method == http.MethodPost:
			role := parts[2]
			if err := reg.UnbindRole(name, role); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "unbound", "name": name, "role": role})
		default:
			http.NotFound(w, r)
		}
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})

	srv := &http.Server{Addr: listen, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
	}()

	log.Printf("boan-llm-registry listening on %s", listen)
	log.Fatal(srv.ListenAndServe())
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
