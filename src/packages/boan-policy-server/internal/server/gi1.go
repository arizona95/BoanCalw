package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-policy-server/internal/policy"
)

// gi1Upload — POST /v1/guardrail/gi1/forbidden. Body: {hash, description,
// replacement}. Hash is computed device-side (boan-proxy) so the original
// image bytes never leave the device — the cloud only sees the 16-hex pHash.
// Appends via OrgPolicy.Update so live-sync subscribers see the new entry
// on the same channel as GT1/GT2 edits. Idempotent on hash.
func (s *Server) gi1Upload(w http.ResponseWriter, r *http.Request, orgID string) {
	var body struct {
		Hash        string `json:"hash"`
		Description string `json:"description"`
		Replacement string `json:"replacement"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}
	hash := strings.ToLower(strings.TrimSpace(body.Hash))
	if len(hash) != 16 {
		http.Error(w, "hash must be 16-hex (64-bit pHash)", http.StatusBadRequest)
		return
	}

	current, err := s.orgPolicy.Get(r.Context(), orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, existing := range current.Guardrail.GI1Forbidden {
		if existing.Hash == hash {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"hash": hash, "duplicate": true})
			return
		}
	}

	description := strings.TrimSpace(body.Description)
	replacement := strings.TrimSpace(body.Replacement)

	merged := append([]policy.GI1ForbiddenImage(nil), current.Guardrail.GI1Forbidden...)
	merged = append(merged, policy.GI1ForbiddenImage{
		Hash:        hash,
		Description: description,
		Replacement: replacement,
		UploadedAt:  time.Now().UTC().Format(time.RFC3339),
	})
	if _, err := s.orgPolicy.Update(r.Context(), orgID, PolicyPatch{GI1Forbidden: &merged}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"hash": hash, "description": description})
}

// gi1Delete — DELETE /v1/guardrail/gi1/forbidden/{hash}. Drops the entry,
// then writes the trimmed list back through OrgPolicy.Update.
func (s *Server) gi1Delete(w http.ResponseWriter, r *http.Request, orgID, hash string) {
	hash = strings.ToLower(strings.TrimSpace(hash))
	current, err := s.orgPolicy.Get(r.Context(), orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	remaining := make([]policy.GI1ForbiddenImage, 0, len(current.Guardrail.GI1Forbidden))
	removed := false
	for _, e := range current.Guardrail.GI1Forbidden {
		if e.Hash == hash {
			removed = true
			continue
		}
		remaining = append(remaining, e)
	}
	if !removed {
		http.Error(w, fmt.Sprintf("hash %s not found", hash), http.StatusNotFound)
		return
	}
	if _, err := s.orgPolicy.Update(r.Context(), orgID, PolicyPatch{GI1Forbidden: &remaining}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// gi2SetDescriptions — PUT /v1/guardrail/gi2/descriptions. Body:
// {"descriptions": [{"description": "회로도", "action": "ask"}, ...]}.
// Replaces the entire list — UI sends the canonical set every save. Empty
// list is allowed (turns GI2 off without removing the GI1 store).
func (s *Server) gi2SetDescriptions(w http.ResponseWriter, r *http.Request, orgID string) {
	var body struct {
		Descriptions []policy.GI2Description `json:"descriptions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := s.orgPolicy.Update(r.Context(), orgID, PolicyPatch{GI2Descriptions: &body.Descriptions}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// gi1Threshold — PUT /v1/guardrail/gi1/threshold. Body: {"threshold": 10}.
// Single-purpose endpoint so the slider in the UI doesn't have to round-trip
// the entire guardrail config.
func (s *Server) gi1Threshold(w http.ResponseWriter, r *http.Request, orgID string) {
	var body struct {
		Threshold int `json:"threshold"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := s.orgPolicy.Update(r.Context(), orgID, PolicyPatch{GI1HammingThreshold: &body.Threshold}); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
