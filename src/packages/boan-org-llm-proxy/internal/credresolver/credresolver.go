// Package credresolver turns {{CREDENTIAL:role}} placeholders into plaintext
// by calling boan-org-credential-gate. This is the single moment at which
// plaintext credentials exist in memory inside boan-org-llm-proxy; they
// are applied to the outbound request and never returned to the caller.
package credresolver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

var placeholder = regexp.MustCompile(`\{\{CREDENTIAL:([A-Za-z0-9_.\-]+)\}\}`)

type resolveRequest struct {
	OrgID      string `json:"org_id"`
	Role       string `json:"role"`
	CallerID   string `json:"caller_id,omitempty"`
	TargetHost string `json:"target_host,omitempty"`
}

type resolveResponse struct {
	Plaintext string `json:"plaintext"`
	Error     string `json:"error,omitempty"`
}

type Resolver struct {
	GateURL   string
	AuthToken string
	client    *http.Client

	// cache is short-lived (TTL below) so that a single /v1/forward request
	// can reuse the same secret across header+body without issuing many
	// round trips. It does NOT survive across requests — entries are pruned.
	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	value     string
	expiresAt time.Time
}

const cacheTTL = 30 * time.Second

func New(gateURL, authToken string) *Resolver {
	return &Resolver{
		GateURL:   strings.TrimRight(gateURL, "/"),
		AuthToken: authToken,
		client:    &http.Client{Timeout: 5 * time.Second},
		cache:     map[string]cacheEntry{},
	}
}

// Resolve replaces every {{CREDENTIAL:role}} placeholder in the given
// headers+body with the plaintext value fetched from the gate. Returns a
// sanitized (plaintext-free) request plus the plaintexts that were
// substituted (so the caller can scrub echoes from the upstream response).
func (r *Resolver) ResolveAll(ctx context.Context, orgID, callerID, targetHost string, headers map[string]string, body []byte) (map[string]string, []byte, []string, error) {
	if r == nil || r.GateURL == "" {
		// resolver not configured; leave placeholders as-is
		return headers, body, nil, nil
	}

	roles := map[string]struct{}{}
	collect := func(s string) {
		for _, m := range placeholder.FindAllStringSubmatch(s, -1) {
			roles[m[1]] = struct{}{}
		}
	}
	for _, v := range headers {
		collect(v)
	}
	collect(string(body))
	if len(roles) == 0 {
		return headers, body, nil, nil
	}

	values := make(map[string]string, len(roles))
	plaintexts := make([]string, 0, len(roles))
	for role := range roles {
		v, err := r.fetch(ctx, orgID, role, callerID, targetHost)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("resolve %q: %w", role, err)
		}
		values[role] = v
		plaintexts = append(plaintexts, v)
	}

	resolvedHeaders := make(map[string]string, len(headers))
	for k, v := range headers {
		resolvedHeaders[k] = substitute(v, values)
	}
	resolvedBody := []byte(substitute(string(body), values))
	return resolvedHeaders, resolvedBody, plaintexts, nil
}

func substitute(s string, values map[string]string) string {
	return placeholder.ReplaceAllStringFunc(s, func(match string) string {
		inner := placeholder.FindStringSubmatch(match)
		if len(inner) < 2 {
			return match
		}
		if v, ok := values[inner[1]]; ok {
			return v
		}
		return match
	})
}

func (r *Resolver) fetch(ctx context.Context, orgID, role, callerID, targetHost string) (string, error) {
	cacheKey := orgID + "/" + role
	r.mu.Lock()
	if e, ok := r.cache[cacheKey]; ok && time.Now().Before(e.expiresAt) {
		r.mu.Unlock()
		return e.value, nil
	}
	r.mu.Unlock()

	reqBody, _ := json.Marshal(resolveRequest{
		OrgID:      orgID,
		Role:       role,
		CallerID:   callerID,
		TargetHost: targetHost,
	})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, r.GateURL+"/v1/resolve", bytes.NewReader(reqBody))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Authorization", "Bearer "+r.AuthToken)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var e resolveResponse
		_ = json.Unmarshal(raw, &e)
		if e.Error != "" {
			return "", errors.New(e.Error)
		}
		return "", fmt.Errorf("credential-gate returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out resolveResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("decode resolve response: %w", err)
	}
	if out.Plaintext == "" {
		return "", errors.New("credential-gate returned empty plaintext")
	}

	r.mu.Lock()
	r.cache[cacheKey] = cacheEntry{value: out.Plaintext, expiresAt: time.Now().Add(cacheTTL)}
	r.mu.Unlock()
	return out.Plaintext, nil
}

// Prune drops expired cache entries. Called periodically.
func (r *Resolver) Prune() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for k, e := range r.cache {
		if now.After(e.expiresAt) {
			delete(r.cache, k)
		}
	}
}

// ScrubEchoes replaces any occurrence of the plaintext credential values in
// the given bytes with "[REDACTED]". Called against upstream response body
// to prevent credential echo leaking back to the local host.
func (r *Resolver) ScrubEchoes(b []byte, plaintexts []string) []byte {
	if len(plaintexts) == 0 {
		return b
	}
	out := b
	for _, p := range plaintexts {
		if p == "" || len(p) < 4 {
			continue
		}
		out = bytes.ReplaceAll(out, []byte(p), []byte("[REDACTED]"))
	}
	return out
}
