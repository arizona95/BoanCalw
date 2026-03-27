package server

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/samsung-sds/boanclaw/boan-policy-server/internal/policy"
	"github.com/samsung-sds/boanclaw/boan-policy-server/internal/signing"
)

type Config struct {
	Listen  string
	DataDir string
	KeyDir  string
}

func LoadConfig() Config {
	return Config{
		Listen:  env("BOAN_LISTEN", ":8080"),
		DataDir: env("BOAN_DATA_DIR", "/data/policies"),
		KeyDir:  env("BOAN_KEY_DIR", "/etc/boan-policy"),
	}
}

type Server struct {
	cfg    Config
	store  *policy.Store
	signer *signing.Signer
}

func New(cfg Config) *Server {
	store := policy.NewStore(cfg.DataDir)
	os.MkdirAll(cfg.KeyDir, 0700)
	signer, _ := signing.LoadOrCreate(cfg.KeyDir+"/ed25519.priv", cfg.KeyDir+"/ed25519.pub")
	return &Server{cfg: cfg, store: store, signer: signer}
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/org/", s.handleOrg)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/pubkey", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string][]byte{"pub": s.signer.Pub})
	})

	srv := &http.Server{Addr: s.cfg.Listen, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
	}()
	return srv.ListenAndServe()
}

func (s *Server) handleOrg(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/org/"), "/")
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	orgID := parts[0]
	rest := strings.Join(parts[1:], "/")

	switch {
	case rest == "policy.json" && r.Method == http.MethodGet:
		s.getPolicy(w, orgID)
	case rest == "policy" && r.Method == http.MethodPost:
		s.updatePolicy(w, r, orgID)
	case rest == "policy/versions" && r.Method == http.MethodGet:
		s.listVersions(w, orgID)
	case strings.HasPrefix(rest, "policy/rollback/") && r.Method == http.MethodPost:
		verStr := strings.TrimPrefix(rest, "policy/rollback/")
		s.rollbackPolicy(w, orgID, verStr)
	case rest == "network-policy.json" && r.Method == http.MethodGet:
		s.getSignedNetworkPolicy(w, orgID)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) getPolicy(w http.ResponseWriter, orgID string) {
	p, err := s.store.Load(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	p.Signature = ""
	sig, _ := s.signer.Sign(p)
	p.Signature = sig
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request, orgID string) {
	var p policy.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p.OrgID = orgID
	p.Version = s.store.NextVersion(orgID)
	p.Signature = ""
	if err := s.store.Save(&p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"version": p.Version})
}

func (s *Server) listVersions(w http.ResponseWriter, orgID string) {
	versions := s.store.ListVersions(orgID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(versions)
}

func (s *Server) rollbackPolicy(w http.ResponseWriter, orgID string, verStr string) {
	ver, err := strconv.Atoi(verStr)
	if err != nil {
		http.Error(w, "invalid version", http.StatusBadRequest)
		return
	}
	old, err := s.store.LoadVersion(orgID, ver)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	old.Version = s.store.NextVersion(orgID)
	old.Signature = ""
	if err := s.store.Save(old); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"rolled_back_to": ver, "new_version": old.Version})
}

func (s *Server) getSignedNetworkPolicy(w http.ResponseWriter, orgID string) {
	p, err := s.store.Load(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	policyDoc := map[string]any{
		"endpoints":  p.Network,
		"updated_at": p.UpdatedAt,
	}
	policyJSON, err := json.Marshal(policyDoc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sig, err := s.signer.SignBytes(policyJSON)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"policy":    json.RawMessage(policyJSON),
		"signature": sig,
	})
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
