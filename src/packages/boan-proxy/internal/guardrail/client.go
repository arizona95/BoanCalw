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
	token   string
	http    *http.Client
}

type EvaluateRequest struct {
	Text        string `json:"text"`
	Mode        string `json:"mode,omitempty"`
	UserEmail   string `json:"user_email,omitempty"`
	AccessLevel string `json:"access_level,omitempty"`
	LLMURL      string `json:"llm_url,omitempty"`   // proxy가 registry에서 가져온 security LLM URL
	LLMModel    string `json:"llm_model,omitempty"` // proxy가 registry에서 가져온 security LLM model
}

type EvaluateResponse struct {
	Decision   string  `json:"decision"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
	Tier       int     `json:"tier,omitempty"`
	Response   string  `json:"response,omitempty"`
}

func New(baseURL string) *Client {
	return NewWithToken(baseURL, "")
}

func NewWithToken(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		token:   token,
		http:    &http.Client{Timeout: 8 * time.Second},
	}
}

func (c *Client) SetToken(t string) { c.token = t }

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
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}

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
			Decision:   "block",
			Reason:     "guardrail server unavailable — fail-closed",
			Confidence: 1,
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
			Decision:   "block",
			Reason:     "wiki guardrail server unavailable — fail-closed",
			Confidence: 1,
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

// GetConstitution — policy-server에서 헌법 텍스트만 조회 (LLM 호출은 proxy가 직접)
func (c *Client) GetConstitution(ctx context.Context, orgID string) (string, error) {
	if c == nil || c.baseURL == "" || strings.TrimSpace(orgID) == "" {
		return "", fmt.Errorf("policy server unavailable")
	}
	url := fmt.Sprintf("%s/org/%s/v1/policy", c.baseURL, orgID)
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("policy server returned %d", resp.StatusCode)
	}
	var p struct {
		Guardrail struct {
			Constitution string `json:"constitution"`
		} `json:"guardrail"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return "", err
	}
	return p.Guardrail.Constitution, nil
}

// GuardrailG1Rule — input_gate 로 전달할 G1 규칙.
type GuardrailG1Rule struct {
	Pattern     string
	Replacement string
	Mode        string // "redact" | "credential" | "block"
}

// GetGuardrailRules — policy-server에서 G1 patterns + G3 wiki hint 조회
// (헌법은 GetConstitution 별도)
type GuardrailRules struct {
	G1Patterns []GuardrailG1Rule
	G3WikiHint string
}

func (c *Client) GetGuardrailRules(ctx context.Context, orgID string) (*GuardrailRules, error) {
	if c == nil || c.baseURL == "" || strings.TrimSpace(orgID) == "" {
		return &GuardrailRules{}, nil
	}
	url := fmt.Sprintf("%s/org/%s/v1/policy", c.baseURL, orgID)
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return &GuardrailRules{}, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return &GuardrailRules{}, nil
	}
	var p struct {
		Guardrail struct {
			G1CustomPatterns []struct {
				Pattern     string `json:"pattern"`
				Description string `json:"description"`
				Replacement string `json:"replacement"`
				Mode        string `json:"mode"`
			} `json:"g1_custom_patterns"`
			G3WikiHint string `json:"g3_wiki_hint"`
		} `json:"guardrail"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return &GuardrailRules{}, nil
	}
	rules := make([]GuardrailG1Rule, 0, len(p.Guardrail.G1CustomPatterns))
	for _, pat := range p.Guardrail.G1CustomPatterns {
		if trimmed := strings.TrimSpace(pat.Pattern); trimmed != "" {
			rules = append(rules, GuardrailG1Rule{
				Pattern:     trimmed,
				Replacement: pat.Replacement,
				Mode:        strings.ToLower(strings.TrimSpace(pat.Mode)),
			})
		}
	}
	return &GuardrailRules{
		G1Patterns: rules,
		G3WikiHint: p.Guardrail.G3WikiHint,
	}, nil
}
