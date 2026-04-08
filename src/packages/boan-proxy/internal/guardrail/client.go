package guardrail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	http    *http.Client
}

type EvaluateRequest struct {
	Text        string `json:"text"`
	Mode        string `json:"mode,omitempty"`
	UserEmail   string `json:"user_email,omitempty"`
	AccessLevel string `json:"access_level,omitempty"`
}

type EvaluateResponse struct {
	Decision   string  `json:"decision"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
	Tier       int     `json:"tier,omitempty"`
	Response   string  `json:"response,omitempty"`
}

func New(baseURL string) *Client {
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		http:    &http.Client{Timeout: 8 * time.Second},
	}
}

func (c *Client) doPost(ctx context.Context, url string, req EvaluateRequest) (*EvaluateResponse, error) {
	raw, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("guardrail server returned %d", resp.StatusCode)
	}

	var out EvaluateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Evaluate(ctx context.Context, orgID string, req EvaluateRequest) (*EvaluateResponse, error) {
	if c == nil || c.baseURL == "" || strings.TrimSpace(orgID) == "" {
		return &EvaluateResponse{
			Decision:   "allow",
			Reason:     "guardrail server unavailable; fail open disabled path not configured",
			Confidence: 0,
			Tier:       1,
		}, nil
	}
	url := fmt.Sprintf("%s/org/%s/v1/guardrail/evaluate", c.baseURL, orgID)
	resp, err := c.doPost(ctx, url, req)
	if err != nil {
		return nil, err
	}
	resp.Tier = 1
	return resp, nil
}

func (c *Client) WikiEvaluate(ctx context.Context, orgID string, req EvaluateRequest) (*EvaluateResponse, error) {
	if c == nil || c.baseURL == "" || strings.TrimSpace(orgID) == "" {
		return &EvaluateResponse{
			Decision:   "allow",
			Reason:     "wiki guardrail server unavailable; fail open",
			Confidence: 0,
			Tier:       2,
		}, nil
	}
	url := fmt.Sprintf("%s/org/%s/v1/guardrail/wiki-evaluate", c.baseURL, orgID)
	resp, err := c.doPost(ctx, url, req)
	if err != nil {
		return nil, err
	}
	resp.Tier = 2
	return resp, nil
}
