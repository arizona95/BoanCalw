// Wiki Graph HTTP handlers — Layer A primitive tools.
// 노드 역할/타입 하드코딩 X. LLM 이 자유롭게 조합하는 그래프 편집 원시 API.
package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/samsung-sds/boanclaw/boan-policy-server/internal/policy"
)

// ── Nodes ─────────────────────────────────────────────────

func (s *Server) wgListNodes(w http.ResponseWriter, orgID string) {
	nodes, err := s.wikiGraph.ListNodes(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(nodes)
}

func (s *Server) wgGetNode(w http.ResponseWriter, orgID, id string) {
	n, err := s.wikiGraph.GetNode(orgID, id)
	if err != nil {
		if errors.Is(err, policy.ErrWikiNodeNotFound) {
			http.Error(w, "node not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(n)
}

func (s *Server) wgCreateNode(w http.ResponseWriter, r *http.Request, orgID string) {
	var body policy.WikiNode
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body.ID = "" // 새로 생성
	if err := s.wikiGraph.UpsertNode(orgID, &body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) wgUpdateNode(w http.ResponseWriter, r *http.Request, orgID, id string) {
	existing, err := s.wikiGraph.GetNode(orgID, id)
	if err != nil {
		if errors.Is(err, policy.ErrWikiNodeNotFound) {
			http.Error(w, "node not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var patch struct {
		Definition *string   `json:"definition,omitempty"`
		Content    *string   `json:"content,omitempty"`
		Tags       *[]string `json:"tags,omitempty"`
		UpdatedBy  *string   `json:"updated_by,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if patch.Definition != nil {
		existing.Definition = *patch.Definition
	}
	if patch.Content != nil {
		existing.Content = *patch.Content
	}
	if patch.Tags != nil {
		existing.Tags = *patch.Tags
	}
	if patch.UpdatedBy != nil {
		existing.CreatedBy = *patch.UpdatedBy // 마지막 편집자 추적 용도로 재사용
	}
	if err := s.wikiGraph.UpsertNode(orgID, existing); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(existing)
}

func (s *Server) wgDeleteNode(w http.ResponseWriter, orgID, id string) {
	if err := s.wikiGraph.DeleteNode(orgID, id); err != nil {
		if errors.Is(err, policy.ErrWikiNodeNotFound) {
			http.Error(w, "node not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ── Edges ─────────────────────────────────────────────────

func (s *Server) wgListEdges(w http.ResponseWriter, orgID string) {
	edges, err := s.wikiGraph.ListEdges(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(edges)
}

func (s *Server) wgCreateEdge(w http.ResponseWriter, r *http.Request, orgID string) {
	var body policy.WikiEdge
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.From == "" || body.To == "" {
		http.Error(w, "from and to are required", http.StatusBadRequest)
		return
	}
	body.ID = ""
	if err := s.wikiGraph.UpsertEdge(orgID, &body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) wgUpdateEdge(w http.ResponseWriter, r *http.Request, orgID, id string) {
	edges, err := s.wikiGraph.ListEdges(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var existing *policy.WikiEdge
	for i := range edges {
		if edges[i].ID == id {
			existing = &edges[i]
			break
		}
	}
	if existing == nil {
		http.Error(w, "edge not found", http.StatusNotFound)
		return
	}
	var patch struct {
		Relation *string  `json:"relation,omitempty"`
		Weight   *float32 `json:"weight,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if patch.Relation != nil {
		existing.Relation = *patch.Relation
	}
	if patch.Weight != nil {
		existing.Weight = *patch.Weight
	}
	if err := s.wikiGraph.UpsertEdge(orgID, existing); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(existing)
}

func (s *Server) wgDeleteEdge(w http.ResponseWriter, orgID, id string) {
	if err := s.wikiGraph.DeleteEdge(orgID, id); err != nil {
		if errors.Is(err, policy.ErrWikiEdgeNotFound) {
			http.Error(w, "edge not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// ── DecisionLog (approve/deny 라벨) ──────────────────────

func (s *Server) wgAppendDecision(w http.ResponseWriter, r *http.Request, orgID string) {
	var body policy.DecisionLog
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.wikiGraph.AppendDecision(orgID, &body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) wgListDecisions(w http.ResponseWriter, r *http.Request, orgID string) {
	limit := 0
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil {
			limit = n
		}
	}
	list, err := s.wikiGraph.ListDecisions(orgID, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(list)
}

// ── ClarificationDialog (LLM↔Human) ──────────────────────

func (s *Server) wgUpsertDialog(w http.ResponseWriter, r *http.Request, orgID string) {
	var body policy.ClarificationDialog
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.wikiGraph.UpsertDialog(orgID, &body); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) wgListDialogs(w http.ResponseWriter, r *http.Request, orgID string) {
	limit := 0
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil {
			limit = n
		}
	}
	list, err := s.wikiGraph.ListDialogs(orgID, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(list)
}
