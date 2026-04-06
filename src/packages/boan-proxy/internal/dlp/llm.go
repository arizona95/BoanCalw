package dlp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type LLMResult struct {
	Level      SLevel
	Confidence float64
}

type LLMDetector struct {
	url    string
	model  string
	client *http.Client
}

func NewLLMDetector(ollamaURL, model string) *LLMDetector {
	return &LLMDetector{
		url:    ollamaURL + "/api/generate",
		model:  strings.TrimSpace(model),
		client: &http.Client{Timeout: 2 * time.Second},
	}
}

type ollamaReq struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResp struct {
	Response string `json:"response"`
}

const systemPrompt = `You are a data sensitivity classifier. Classify the following text:
- S4: Contains trade secrets, confidential business strategy, unreleased product info
- S3: Contains PII, internal system info, credentials, employee data
- S2: General work content, internal processes, non-sensitive business data
- S1: Public information, generic code patterns, documentation
Respond with ONLY the classification and confidence as: S1 0.95`

func (d *LLMDetector) Classify(ctx context.Context, text string) (SLevel, error) {
	r, err := d.ClassifyDetailed(ctx, text)
	if err != nil {
		return SLevel1, err
	}
	return r.Level, nil
}

func (d *LLMDetector) ClassifyDetailed(ctx context.Context, text string) (*LLMResult, error) {
	if d == nil || d.model == "" {
		return nil, fmt.Errorf("llm detector disabled")
	}
	if len(text) > 2000 {
		text = text[:2000]
	}
	body, _ := json.Marshal(ollamaReq{
		Model:  d.model,
		Prompt: systemPrompt + "\n\nText: " + text,
		Stream: false,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("llm detector unavailable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("llm detector returned status %d", resp.StatusCode)
	}

	var out ollamaResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return parseResult(strings.TrimSpace(out.Response)), nil
}

func parseResult(s string) *LLMResult {
	r := &LLMResult{Level: SLevel1, Confidence: 0.5}
	r.Level = parseLevel(s)
	for _, p := range strings.Fields(s) {
		if v, err := strconv.ParseFloat(p, 64); err == nil && v > 0 && v <= 1 {
			r.Confidence = v
			break
		}
	}
	return r
}

func parseLevel(s string) SLevel {
	switch {
	case strings.Contains(s, "S4"):
		return SLevel4
	case strings.Contains(s, "S3"):
		return SLevel3
	case strings.Contains(s, "S2"):
		return SLevel2
	default:
		return SLevel1
	}
}
