package proxy

import (
	"encoding/json"
	"net/http"
	"time"
)

func (s *Server) StartAdmin() {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck
	})

	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/status/dlp", s.handleDLPStatus)
	mux.HandleFunc("/status/network-gate", s.handleGateStatus)
	mux.HandleFunc("/status/credentials", s.handleCredentialStatus)
	mux.HandleFunc("/status/routing", s.handleRoutingStatus)

	srv := &http.Server{
		Addr:              s.cfg.AdminListen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = srv.ListenAndServe()
	}()
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	dlpStats := s.dlpEng.GetStats()
	auditTotal := uint64(0)
	auditBlocked := uint64(0)
	otelConnected := false
	if s.audit != nil {
		auditTotal = s.audit.TotalEvents()
		auditBlocked = s.audit.BlockedEvents()
		otelConnected = s.audit.IsConnected()
	}

	status := map[string]any{
		"status":    "ok",
		"org":       s.cfg.OrgID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"dlp": map[string]any{
			"rules_loaded":   s.dlpRulesLoaded(),
			"total_inspected": dlpStats.TotalInspected,
			"total_blocked":  dlpStats.TotalBlocked,
			"total_redacted": dlpStats.TotalRedacted,
			"total_allowed":  dlpStats.TotalAllowed,
		},
		"network_gate": map[string]any{
			"endpoint_count": s.gate.EndpointCount(),
			"last_fetch":     s.gate.LastFetch().Format(time.RFC3339),
			"allowed":        s.gate.StatsAllowed(),
			"blocked":        s.gate.StatsBlocked(),
		},
		"credentials": map[string]any{
			"count":  s.creds.CredentialCount(),
			"status": s.creds.StatusSummary(),
		},
		"routing": map[string]any{
			"to_security":  s.router.SecurityRouted(),
			"to_usability": s.router.UsabilityRouted(),
		},
		"tls": map[string]any{
			"cache_size": s.ca.CacheSize(),
		},
		"audit": map[string]any{
			"otel_connected": otelConnected,
			"total_events":   auditTotal,
			"blocked_events": auditBlocked,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status) //nolint:errcheck
}

func (s *Server) handleDLPStatus(w http.ResponseWriter, _ *http.Request) {
	stats := s.dlpEng.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"rules_loaded":    s.dlpRulesLoaded(),
		"total_inspected": stats.TotalInspected,
		"total_blocked":   stats.TotalBlocked,
		"total_redacted":  stats.TotalRedacted,
		"total_allowed":   stats.TotalAllowed,
	})
}

func (s *Server) handleGateStatus(w http.ResponseWriter, _ *http.Request) {
	count := s.gate.EndpointCount()
	if count == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"status":         "no_policy",
			"endpoint_count": 0,
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"status":         "ok",
		"endpoint_count": count,
		"last_fetch":     s.gate.LastFetch().Format(time.RFC3339),
	})
}

func (s *Server) handleCredentialStatus(w http.ResponseWriter, _ *http.Request) {
	summary := s.creds.StatusSummary()
	allOK := true
	for _, st := range summary {
		if st != "ok" {
			allOK = false
			break
		}
	}
	code := http.StatusOK
	if !allOK {
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"count":  len(summary),
		"all_ok": allOK,
		"status": summary,
	})
}

func (s *Server) handleRoutingStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"to_security":  s.router.SecurityRouted(),
		"to_usability": s.router.UsabilityRouted(),
	})
}

func (s *Server) dlpRulesLoaded() int {
	return s.dlpEng.RulesCount()
}
