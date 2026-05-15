package guardrail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/imagehash"
	"golang.org/x/sync/singleflight"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client

	// image-gate cache. Avoid fetching /v1/policy on every image transfer —
	// store the decoded Store + GI2 descriptions per org and rebuild only when
	// the policy version bumps (TTL fallback at gi1CacheTTL).
	imgMu    sync.RWMutex
	imgState map[string]*imageGateState
	imgGroup singleflight.Group
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
		baseURL:  strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		token:    token,
		http:     &http.Client{Timeout: 8 * time.Second},
		imgState: make(map[string]*imageGateState),
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

// GI2Description — 자연어 설명. Vision-LLM 이 이걸로 매칭 판정.
// Action: "ask" (HITL 로 라우팅) 또는 "block" (즉시 차단).
type GI2Description struct {
	Description string
	Action      string
}

// imageGateState — image-gate 전체 상태. boan-proxy 가 1 org 당 1 인스턴스를
// 메모리에 캐싱하고, 정책 버전이 올라갈 때만 fetch + rebuild 한다. 10K 항목
// 기준으로 fetch ~50ms, decode + Store 빌드 ~5ms, gate evaluation ~50µs.
type imageGateState struct {
	store        *imagehash.Store
	descriptions []GI2Description
	policyVer    int
	fetchedAt    time.Time
}

// gi1CacheTTL — 정책 버전이 안 바뀌어도 이 만큼 지나면 한 번은 refetch.
// SSE 가 끊긴 사이 정책이 바뀌었어도 30s 안에는 따라잡도록.
const gi1CacheTTL = 30 * time.Second

// GI1Store — gate hot path 에서 호출. cache 안에 같은 정책 버전 store 가
// 있고 TTL 내라면 즉시 반환, 아니면 정책 fetch + rebuild. 동시 호출이 들어와도
// fetch 는 한 번만 일어나게 singleflight 로 묶는다 (10K 정책 download 가
// 여러 번 동시에 도는 걸 방지).
func (c *Client) GI1Store(ctx context.Context, orgID string) (*imagehash.Store, []GI2Description, error) {
	if c == nil || c.baseURL == "" || strings.TrimSpace(orgID) == "" {
		return imagehash.NewStore(), nil, nil
	}
	c.imgMu.RLock()
	st := c.imgState[orgID]
	c.imgMu.RUnlock()
	if st != nil && time.Since(st.fetchedAt) < gi1CacheTTL {
		return st.store, st.descriptions, nil
	}

	v, err, _ := c.imgGroup.Do(orgID, func() (any, error) {
		return c.refreshGI1(ctx, orgID)
	})
	if err != nil {
		if st != nil {
			// fetch 실패 시 stale 인덱스라도 그대로 쓰는 게 fail-open 보다 안전.
			return st.store, st.descriptions, nil
		}
		return imagehash.NewStore(), nil, err
	}
	refreshed := v.(*imageGateState)
	return refreshed.store, refreshed.descriptions, nil
}

// InvalidateImageGate — policysync 이벤트 (정책 버전 변화) 가 들어왔을 때
// 호출하면 다음 GI1Store 호출에서 강제로 refetch 한다.
func (c *Client) InvalidateImageGate(orgID string) {
	c.imgMu.Lock()
	delete(c.imgState, orgID)
	c.imgMu.Unlock()
}

func (c *Client) refreshGI1(ctx context.Context, orgID string) (*imageGateState, error) {
	url := fmt.Sprintf("%s/org/%s/v1/policy", c.baseURL, orgID)
	httpReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if c.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("policy fetch returned %d", resp.StatusCode)
	}
	var p struct {
		Version   int `json:"version"`
		Guardrail struct {
			GI1Forbidden []struct {
				Hash        string `json:"hash"`
				Description string `json:"description"`
				Replacement string `json:"replacement"`
			} `json:"gi1_forbidden"`
			GI1HammingThreshold int `json:"gi1_hamming_threshold"`
			GI2Descriptions     []struct {
				Description string `json:"description"`
				Action      string `json:"action"`
			} `json:"gi2_descriptions"`
		} `json:"guardrail"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, err
	}
	threshold := p.Guardrail.GI1HammingThreshold
	if threshold <= 0 {
		threshold = 10
	}
	rawForbidden := make([]imagehash.Forbidden, 0, len(p.Guardrail.GI1Forbidden))
	for _, f := range p.Guardrail.GI1Forbidden {
		if strings.TrimSpace(f.Hash) == "" {
			continue
		}
		rawForbidden = append(rawForbidden, imagehash.Forbidden{
			Hash:        f.Hash,
			Description: f.Description,
			Replacement: f.Replacement,
		})
	}

	c.imgMu.Lock()
	prev := c.imgState[orgID]
	if prev != nil && prev.store != nil && prev.policyVer == p.Version {
		// same policy version — refresh fetchedAt and reuse the index slice.
		prev.fetchedAt = time.Now()
		c.imgMu.Unlock()
		return prev, nil
	}
	c.imgMu.Unlock()

	store := imagehash.NewStore()
	store.Rebuild(rawForbidden, threshold, p.Version)
	descs := make([]GI2Description, 0, len(p.Guardrail.GI2Descriptions))
	for _, d := range p.Guardrail.GI2Descriptions {
		descs = append(descs, GI2Description{Description: d.Description, Action: d.Action})
	}

	st := &imageGateState{
		store:        store,
		descriptions: descs,
		policyVer:    p.Version,
		fetchedAt:    time.Now(),
	}
	c.imgMu.Lock()
	c.imgState[orgID] = st
	c.imgMu.Unlock()
	return st, nil
}

// GuardrailGT1Rule — input_gate 로 전달할 GT1 (text 정규식) 규칙.
type GuardrailGT1Rule struct {
	Pattern     string
	Replacement string
	Mode        string // "redact" | "credential" | "block"
}

// GuardrailG1Rule is an alias kept for callers still on the old name.
// TODO: remove once all callers migrate to GuardrailGT1Rule.
type GuardrailG1Rule = GuardrailGT1Rule

// GuardrailRules — policy-server에서 GT1 patterns + GT3 wiki hint 조회
// (헌법은 GetConstitution 별도). 이미지 가드레일(GI*)은 별도 fetcher 사용.
type GuardrailRules struct {
	GT1Patterns []GuardrailGT1Rule
	GT3WikiHint string
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
			GT1Patterns []struct {
				Pattern     string `json:"pattern"`
				Description string `json:"description"`
				Replacement string `json:"replacement"`
				Mode        string `json:"mode"`
			} `json:"g1_custom_patterns"`
			GT3WikiHint string `json:"g3_wiki_hint"`
		} `json:"guardrail"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return &GuardrailRules{}, nil
	}
	rules := make([]GuardrailGT1Rule, 0, len(p.Guardrail.GT1Patterns))
	for _, pat := range p.Guardrail.GT1Patterns {
		if trimmed := strings.TrimSpace(pat.Pattern); trimmed != "" {
			rules = append(rules, GuardrailGT1Rule{
				Pattern:     trimmed,
				Replacement: pat.Replacement,
				Mode:        strings.ToLower(strings.TrimSpace(pat.Mode)),
			})
		}
	}
	return &GuardrailRules{
		GT1Patterns: rules,
		GT3WikiHint: p.Guardrail.GT3WikiHint,
	}, nil
}
