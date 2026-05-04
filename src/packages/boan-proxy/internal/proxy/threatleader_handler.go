package proxy

// threatleader_handler.go — /api/threat-leader/* HTTP endpoints.
//
//   GET  /api/threat-leader/proposals             — 현재 top 5 + last_fetch_at
//   POST /api/threat-leader/refresh               — 즉시 fetch 트리거 (non-blocking)
//   POST /api/threat-leader/proposals/{id}/accept — KillChain rule 추가 (auto=true) + seen 마킹
//   POST /api/threat-leader/proposals/{id}/reject — ignored 마킹
//
// Accept 시 auto=true 로 등록 → 이후 사용자 컴퓨터에서 매칭 process 발견 시 즉시
// 격리 → 포렌식 disk snapshot → STOP → DELETE.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/killchain"
)

func (s *Server) registerThreatLeaderHandlers(mux *http.ServeMux) {
	if s.threatLeader == nil {
		return
	}
	mux.HandleFunc("/api/threat-leader/proposals", func(w http.ResponseWriter, r *http.Request) {
		if threatLeaderCORS(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		st := s.threatLeader.Snapshot()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"last_fetch_at": st.LastFetchAt,
			"proposals":     st.Latest,
		})
	})

	mux.HandleFunc("/api/threat-leader/refresh", func(w http.ResponseWriter, r *http.Request) {
		if threatLeaderCORS(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if !s.requireOwner(w, r) {
			return
		}
		if s.threatRefresh != nil {
			s.threatRefresh.TriggerNow()
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "triggered",
			"message": "OSV fetch 진행 중. 30 초 후 GET 으로 결과 확인.",
		})
	})

	mux.HandleFunc("/api/threat-leader/proposals/", func(w http.ResponseWriter, r *http.Request) {
		if threatLeaderCORS(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if !s.requireOwner(w, r) {
			return
		}
		// /api/threat-leader/proposals/{id}/{accept|reject}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/threat-leader/proposals/"), "/")
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		id, action := parts[0], parts[1]
		w.Header().Set("Content-Type", "application/json")
		switch action {
		case "accept":
			s.handleThreatLeaderAccept(w, id)
		case "reject":
			if err := s.threatLeader.MarkIgnored(id); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ignored", "id": id})
		default:
			http.NotFound(w, r)
		}
	})
}

// handleThreatLeaderAccept — Threat Leader 의 advisory 를 KillChain rule (auto=true) 로 등록.
// Rule 등록 후 store 의 Seen 에 마킹해서 latest 에서 즉시 사라짐.
func (s *Server) handleThreatLeaderAccept(w http.ResponseWriter, id string) {
	prop, ok := s.threatLeader.FindProposal(id)
	if !ok {
		http.Error(w, fmt.Sprintf("proposal not found: %s", id), http.StatusNotFound)
		return
	}
	if s.killchain == nil {
		http.Error(w, "kill chain store not initialized", http.StatusServiceUnavailable)
		return
	}

	// rule description — admin 이 KillChain Rules 탭에서 한 눈에 출처 알 수 있게.
	desc := fmt.Sprintf(
		"Threat Leader (%s) — %s\n\nPackage: %s:%s %s\nSeverity: %s%s\nSummary: %s\nReference: %s\n\n%s",
		prop.ID,
		prop.PublishedAt.Format("2006-01-02"),
		prop.Ecosystem, prop.PackageName, prop.VersionsAffected,
		strings.ToUpper(prop.Severity),
		cvssDisplay(prop.CVSSScore),
		prop.Summary,
		prop.ReferenceURL,
		prop.Description,
	)

	rule := killchain.Rule{
		Name:        prop.SuggestedRuleName,
		ProcessName: prop.SuggestedProcess,
		Auto:        true, // 사용자 결정 — Accept 시 즉시 발동.
		Description: desc,
		CreatedAt:   time.Now().UTC(),
	}
	added, err := s.killchain.AddRule(rule)
	if err != nil {
		http.Error(w, "rule 추가 실패: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.threatLeader.MarkSeen(id); err != nil {
		// rule 은 등록됨 — 부분 실패 허용.
		http.Error(w, "rule 등록은 됐으나 seen 마킹 실패: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "rule_added",
		"id":      id,
		"rule_id": added.ID,
		"auto":    added.Auto,
		"message": fmt.Sprintf("Kill Chain rule 등록 (auto=true). 매칭 process '%s' 발견 시 즉시 격리 → 포렌식 → 폐기.", prop.SuggestedProcess),
	})
}

// threatLeaderCORS — admin.go 의 cors closure 와 같은 동작 (이 파일에서 접근 불가).
func threatLeaderCORS(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Cookie")
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

func cvssDisplay(v float64) string {
	if v <= 0 {
		return ""
	}
	return fmt.Sprintf(" (CVSS %.1f)", v)
}
