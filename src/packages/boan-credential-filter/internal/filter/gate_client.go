package filter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GateClient is a thin HTTP wrapper around boan-org-credential-gate. When
// configured, the local credential-filter delegates ALL credential
// operations to the cloud gate and stores nothing on disk.
type GateClient struct {
	URL       string
	AuthToken string
	client    *http.Client
}

func NewGateClient(url, authToken string) *GateClient {
	return &GateClient{
		URL:       strings.TrimRight(url, "/"),
		AuthToken: authToken,
		client:    &http.Client{Timeout: 8 * time.Second},
	}
}

type gateMeta struct {
	Role      string    `json:"role"`
	OrgID     string    `json:"org_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type gateResolveRequest struct {
	OrgID      string `json:"org_id"`
	Role       string `json:"role"`
	CallerID   string `json:"caller_id,omitempty"`
	TargetHost string `json:"target_host,omitempty"`
}

type gateResolveResponse struct {
	Plaintext string `json:"plaintext"`
}

func (g *GateClient) do(ctx context.Context, method, path string, body any) (int, []byte, error) {
	var bodyReader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.URL+path, bodyReader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.AuthToken)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, nil
}

// Put stores a credential in the cloud gate. Plaintext never persists locally.
func (g *GateClient) Put(ctx context.Context, orgID, role, key string) error {
	status, body, err := g.do(ctx, http.MethodPost, "/v1/credentials/"+orgID, map[string]string{
		"role": role,
		"key":  key,
	})
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("credential-gate put %d: %s", status, strings.TrimSpace(string(body)))
	}
	return nil
}

// Resolve fetches plaintext for a credential. Returns "" if not found.
func (g *GateClient) Resolve(ctx context.Context, orgID, role string) (string, error) {
	status, body, err := g.do(ctx, http.MethodPost, "/v1/resolve", gateResolveRequest{
		OrgID: orgID, Role: role, CallerID: "boan-credential-filter",
	})
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", nil
	}
	if status >= 300 {
		return "", fmt.Errorf("credential-gate resolve %d: %s", status, strings.TrimSpace(string(body)))
	}
	var out gateResolveResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	return out.Plaintext, nil
}

// List returns metadata for all credentials belonging to orgID.
func (g *GateClient) List(ctx context.Context, orgID string) ([]gateMeta, error) {
	status, body, err := g.do(ctx, http.MethodGet, "/v1/credentials/"+orgID, nil)
	if err != nil {
		return nil, err
	}
	if status >= 300 {
		return nil, fmt.Errorf("credential-gate list %d: %s", status, strings.TrimSpace(string(body)))
	}
	var out []gateMeta
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Delete removes a credential from the cloud gate.
func (g *GateClient) Delete(ctx context.Context, orgID, role string) error {
	status, body, err := g.do(ctx, http.MethodDelete, "/v1/credentials/"+orgID+"/"+role, nil)
	if err != nil {
		return err
	}
	if status == http.StatusNotFound {
		return nil
	}
	if status >= 300 {
		return fmt.Errorf("credential-gate delete %d: %s", status, strings.TrimSpace(string(body)))
	}
	return nil
}
