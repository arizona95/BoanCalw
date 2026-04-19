package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/auth"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/killchain"
)

// registerKillChainEndpoints — mount kill chain HTTP surface.
//
// Routes:
//   GET    /api/kill-chain/rules           — list
//   POST   /api/kill-chain/rules           — add (owner only; body: name, process_name, auto, description)
//   DELETE /api/kill-chain/rules/{id}
//   PATCH  /api/kill-chain/rules/{id}      — toggle auto (body: {auto: bool})
//   GET    /api/kill-chain/incidents?limit=N
//   GET    /api/kill-chain/incidents/{id}
//   POST   /api/kill-chain/incidents/trigger — manual trigger (body: target_email)
//   POST   /api/kill-chain/event           — Wazuh / EDR webhook (body: alert JSON)
func (s *Server) registerKillChainEndpoints(mux *http.ServeMux) {
	if s.killchain == nil || s.killchainRun == nil {
		// store 초기화 실패 — 기능 비활성화.
		return
	}

	// ── rules ─────────────────────────────────────────────────────────
	mux.HandleFunc("/api/kill-chain/rules", func(w http.ResponseWriter, r *http.Request) {
		if killChainCORS(w, r) { return }
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(s.killchain.ListRules())
		case http.MethodPost:
			if !s.requireOwner(w, r) { return }
			var body struct {
				Name        string `json:"name"`
				ProcessName string `json:"process_name"`
				Auto        bool   `json:"auto"`
				Description string `json:"description"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest); return
			}
			created, err := s.killchain.AddRule(killchain.Rule{
				Name: body.Name, ProcessName: body.ProcessName,
				Auto: body.Auto, Description: body.Description,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest); return
			}
			_ = json.NewEncoder(w).Encode(created)
		default:
			http.NotFound(w, r)
		}
	})

	mux.HandleFunc("/api/kill-chain/rules/", func(w http.ResponseWriter, r *http.Request) {
		if killChainCORS(w, r) { return }
		id := strings.TrimPrefix(r.URL.Path, "/api/kill-chain/rules/")
		if id == "" { http.NotFound(w, r); return }
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodDelete:
			if !s.requireOwner(w, r) { return }
			if err := s.killchain.DeleteRule(id); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound); return
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodPatch:
			if !s.requireOwner(w, r) { return }
			var body struct{ Auto bool `json:"auto"` }
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest); return
			}
			if err := s.killchain.UpdateRuleAuto(id, body.Auto); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound); return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "auto": body.Auto})
		default:
			http.NotFound(w, r)
		}
	})

	// ── incidents ─────────────────────────────────────────────────────
	mux.HandleFunc("/api/kill-chain/incidents", func(w http.ResponseWriter, r *http.Request) {
		if killChainCORS(w, r) { return }
		if r.Method != http.MethodGet { http.NotFound(w, r); return }
		w.Header().Set("Content-Type", "application/json")
		limit := 100
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil { limit = n }
		}
		_ = json.NewEncoder(w).Encode(s.killchain.ListIncidents(limit))
	})

	mux.HandleFunc("/api/kill-chain/incidents/", func(w http.ResponseWriter, r *http.Request) {
		if killChainCORS(w, r) { return }
		w.Header().Set("Content-Type", "application/json")
		rest := strings.TrimPrefix(r.URL.Path, "/api/kill-chain/incidents/")
		// /trigger — special path
		if rest == "trigger" {
			if r.Method != http.MethodPost { http.NotFound(w, r); return }
			s.handleKillChainTrigger(w, r)
			return
		}
		if rest == "" { http.NotFound(w, r); return }
		if r.Method != http.MethodGet { http.NotFound(w, r); return }
		inc, ok := s.killchain.GetIncident(rest)
		if !ok {
			http.Error(w, "incident not found", http.StatusNotFound); return
		}
		_ = json.NewEncoder(w).Encode(inc)
	})

	// ── event ingest (Wazuh / Fluent Bit) ─────────────────────────────
	mux.HandleFunc("/api/kill-chain/event", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost { http.NotFound(w, r); return }
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest); return
		}
		// event shape (flexible — Wazuh / Fluent Bit / manual test 모두 수용):
		//   process_name : 감지된 프로세스 이름
		//   target_email : 이벤트 발생 VM 의 소유자 이메일
		processName, _ := body["process_name"].(string)
		targetEmail, _ := body["target_email"].(string)
		processName = strings.TrimSpace(processName)
		targetEmail = strings.TrimSpace(targetEmail)
		if processName == "" || targetEmail == "" {
			http.Error(w, `{"error":"process_name + target_email required"}`, http.StatusBadRequest)
			return
		}
		rule := s.killchain.MatchProcess(processName)
		resp := map[string]any{
			"matched":      rule != nil,
			"process_name": processName,
		}
		if rule == nil {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		resp["rule_id"] = rule.ID
		resp["rule_name"] = rule.Name
		resp["auto"] = rule.Auto
		if !rule.Auto {
			// 룰은 매칭됐지만 auto 가 꺼져있음 → incident 만 pending 상태로 기록.
			inc, _ := s.killchain.CreateIncident(killchain.Incident{
				Trigger:      "auto-wazuh",
				RuleID:       rule.ID,
				RuleName:     rule.Name,
				TargetEmail:  targetEmail,
				MatchedEvent: body,
				Status:       "pending-manual",
			})
			resp["incident_id"] = inc.ID
			resp["action"] = "pending-manual"
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		// auto=true → 즉시 실행.
		incID, err := s.triggerKillChain(r, targetEmail, rule, body, "auto-wazuh")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError); return
		}
		resp["incident_id"] = incID
		resp["action"] = "started"
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// handleKillChainTrigger — manual trigger 버튼.
func (s *Server) handleKillChainTrigger(w http.ResponseWriter, r *http.Request) {
	if !s.requireOwner(w, r) { return }
	var body struct {
		TargetEmail string `json:"target_email"`
		RuleID      string `json:"rule_id,omitempty"`
		Reason      string `json:"reason,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest); return
	}
	body.TargetEmail = strings.TrimSpace(body.TargetEmail)
	if body.TargetEmail == "" {
		http.Error(w, `{"error":"target_email required"}`, http.StatusBadRequest); return
	}
	var rule *killchain.Rule
	if body.RuleID != "" {
		for _, r := range s.killchain.ListRules() {
			if r.ID == body.RuleID {
				rr := r
				rule = &rr
				break
			}
		}
	}
	matched := map[string]any{"reason": body.Reason, "source": "manual"}
	incID, err := s.triggerKillChain(r, body.TargetEmail, rule, matched, "manual")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError); return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"incident_id": incID, "status": "started"})
}

// triggerKillChain — target_email 로 workstation 찾은 뒤 runner 시작.
func (s *Server) triggerKillChain(
	r *http.Request,
	targetEmail string,
	rule *killchain.Rule,
	matchedEvent map[string]any,
	trigger string,
) (string, error) {
	user, err := s.users.Get(targetEmail)
	if err != nil || user == nil {
		return "", fmt.Errorf("user not found: %s", targetEmail)
	}
	if user.Workstation == nil || strings.TrimSpace(user.Workstation.InstanceID) == "" {
		return "", fmt.Errorf("user %s has no workstation to kill", targetEmail)
	}
	inc := killchain.Incident{
		Trigger:      trigger,
		TargetEmail:  targetEmail,
		MatchedEvent: matchedEvent,
	}
	if rule != nil {
		inc.RuleID = rule.ID
		inc.RuleName = rule.Name
	}
	if sess, _ := auth.SessionFromRequest(r, s.authProv); sess != nil {
		inc.Requester = sess.Email
	}
	created, err := s.killchainRun.Run(r.Context(), inc, user.Workstation)
	if err != nil {
		return "", err
	}
	return created.ID, nil
}

// killChainCORS — admin.go cors closure 와 동일. 별도 파일에서 재사용 위해 복제.
func killChainCORS(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

// requireOwner — admin 작업용 guard. 세션이 owner / primary_owner 인지 확인.
func (s *Server) requireOwner(w http.ResponseWriter, r *http.Request) bool {
	sess, err := auth.SessionFromRequest(r, s.authProv)
	if err != nil || sess == nil {
		http.Error(w, "authentication required", http.StatusUnauthorized); return false
	}
	role := strings.ToLower(string(sess.Role))
	if role == "owner" || role == "primary_owner" {
		return true
	}
	http.Error(w, "owner role required", http.StatusForbidden)
	return false
}
