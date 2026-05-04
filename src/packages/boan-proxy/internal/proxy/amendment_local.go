// amendment_local.go — 헌법(G2) / G1 정규식 개정안 제안을 proxy-local 에서 생성.
//
// 기존에는 policy-server Cloud Run 의 /v1/guardrail/propose-amendment 로 위임했다.
// 그러나 Cloud Run 에는 LLM 자격이 직접 바인딩되지 않고, 시스템의 모든 LLM 호출은
// 단일 egress (org-llm-proxy) 를 경유해야 한다.
//
// 따라서 여기서는:
//   1) orgClient.GetPolicy 로 현재 헌법/G1 패턴을 가져오고
//   2) orgClient.GetTrainingLog 로 최근 HITL 판정 기록을 가져오고
//   3) LLM Registry 의 agentic_iterate → g3 바인딩으로 LLM 을 선택한 뒤
//   4) s.callRegistryLLM 으로 호출 (→ dispatchLLMRequest → org-llm-proxy Cloud Run)
//   5) 응답 JSON 에서 {diff, reasoning} 를 파싱
//
// 이 경로는 "모든 LLM 호출은 반드시 org-llm-proxy 를 경유한다" 라는 단일 egress
// 원칙을 지킨다.

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/orgserver"
)

type localAmendmentProposal struct {
	Diff      string `json:"diff"`
	Reasoning string `json:"reasoning"`
}

// flexibleAmendment — LLM 이 diff 를 string 이 아니라 array/object 로 내보내는
// 경우도 허용하는 유연 파싱용. 파싱 후 localAmendmentProposal 로 정규화.
type flexibleAmendment struct {
	Diff      json.RawMessage `json:"diff"`
	Reasoning string          `json:"reasoning"`
}

// selectAmendmentLLM — agentic_iterate → g3 순으로 LLM Registry 바인딩 조회.
func (s *Server) selectAmendmentLLM(ctx context.Context) (*registryLLM, error) {
	if entry, err := s.loadLLMByRole(ctx, "agentic_iterate"); err == nil && entry != nil {
		return entry, nil
	}
	if entry, err := s.loadLLMByRole(ctx, "g3"); err == nil && entry != nil {
		return entry, nil
	}
	return nil, fmt.Errorf("LLM Registry 에 role=agentic_iterate 또는 role=g3 로 바인딩된 LLM 없음")
}

// guardrailContextFromPolicy — policy map 에서 guardrail 서브필드 추출.
// {constitution, g1_patterns} 반환.
func guardrailContextFromPolicy(policy map[string]any) (constitution string, g1Patterns []map[string]any) {
	g, _ := policy["guardrail"].(map[string]any)
	if g == nil {
		return
	}
	constitution, _ = g["constitution"].(string)
	if raw, ok := g["g1_custom_patterns"].([]any); ok {
		for _, item := range raw {
			if m, ok := item.(map[string]any); ok {
				g1Patterns = append(g1Patterns, m)
			}
		}
	}
	return
}

// formatRecentDecisions — training log 최근 N 건을 시스템 프롬프트 포맷으로 직렬화.
func formatRecentDecisions(log []map[string]any, limit int) string {
	if len(log) == 0 {
		return ""
	}
	start := 0
	if limit > 0 && len(log) > limit {
		start = len(log) - limit
	}
	var sb strings.Builder
	sb.WriteString("Recent guardrail decisions:\n")
	for _, d := range log[start:] {
		text, _ := d["text"].(string)
		reason, _ := d["reason"].(string)
		decision, _ := d["decision"].(string)
		source, _ := d["source"].(string)
		if len(text) > 60 {
			text = text[:60] + "…"
		}
		sb.WriteString(fmt.Sprintf("- text=%q reason=%q → %s (source=%s)\n",
			text, reason, decision, source))
	}
	return sb.String()
}

// parseAmendmentContent — LLM 응답 content 에서 첫 JSON 오브젝트를 뽑아
// {diff, reasoning} 로 파싱. diff 가 string 이 아니라 array/object 로 내려와도
// 문자열로 정규화 (G1 prompt 가 diff 를 string 으로 강제해도 CoT 모델이 종종
// array 로 내보냄).
func parseAmendmentContent(content string) (*localAmendmentProposal, error) {
	content = strings.TrimSpace(content)
	if content == "" {
		return nil, fmt.Errorf("amendment llm returned no content")
	}
	obj := extractFirstJSONObject(content)
	if obj == "" {
		obj = content
	}
	var flex flexibleAmendment
	if err := json.Unmarshal([]byte(obj), &flex); err != nil {
		return nil, fmt.Errorf("amendment json parse: %w (content=%s)", err, truncateStr(content, 200))
	}
	diffStr := ""
	if len(flex.Diff) > 0 {
		var s string
		if err := json.Unmarshal(flex.Diff, &s); err == nil {
			diffStr = s
		} else {
			// diff 가 array 또는 object: 각 요소를 "+" prefix 가진 line 으로 직렬화.
			var items []any
			if err := json.Unmarshal(flex.Diff, &items); err == nil {
				var lines []string
				for _, it := range items {
					switch v := it.(type) {
					case string:
						lines = append(lines, ensurePlusPrefix(v))
					case map[string]any:
						// {"pattern":"...","description":"...","mode":"..."} 형식 예상
						pat, _ := v["pattern"].(string)
						desc, _ := v["description"].(string)
						mode, _ := v["mode"].(string)
						if pat != "" {
							lines = append(lines, fmt.Sprintf("+%s | %s | %s",
								pat, desc, firstNonEmptyStr(mode, "block")))
						}
					default:
						b, _ := json.Marshal(v)
						lines = append(lines, ensurePlusPrefix(string(b)))
					}
				}
				diffStr = strings.Join(lines, "\n")
			} else {
				// 모르면 원본을 string 으로.
				diffStr = string(flex.Diff)
			}
		}
	}
	return &localAmendmentProposal{
		Diff:      strings.TrimSpace(diffStr),
		Reasoning: strings.TrimSpace(flex.Reasoning),
	}, nil
}

func ensurePlusPrefix(s string) string {
	t := strings.TrimSpace(s)
	if t == "" {
		return t
	}
	if strings.HasPrefix(t, "+") {
		return t
	}
	return "+" + t
}

func firstNonEmptyStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// proposeAmendmentLocal — 헌법(G2) 개정안 제안을 proxy-local 에서 생성.
// org-llm-proxy 를 경유하는 단일 egress 경로로 LLM 호출.
func (s *Server) proposeAmendmentLocal(ctx context.Context, orgClient *orgserver.Client, orgID string) (*localAmendmentProposal, error) {
	entry, err := s.selectAmendmentLLM(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := orgClient.GetPolicy(orgID)
	if err != nil {
		return nil, fmt.Errorf("get policy: %w", err)
	}
	constitution, _ := guardrailContextFromPolicy(policy)

	trainingLog, _ := orgClient.GetTrainingLog(orgID)
	wikiContext := formatRecentDecisions(trainingLog, 100)

	systemPrompt := fmt.Sprintf(
		"You are the BoanClaw Constitution Amendment Advisor.\n\n"+
			"Current constitution:\n%s\n\n"+
			"%s\n"+
			"Based on the pattern of recent decisions, propose amendments to the constitution.\n"+
			"Return strict JSON: {\"diff\":\"unified diff of the constitution (lines starting with + for additions, - for removals)\",\"reasoning\":\"why this amendment is needed\"}",
		strings.TrimSpace(constitution), wikiContext,
	)
	userPrompt := "Propose constitution amendments based on the accumulated wiki knowledge."

	out, err := s.callRegistryLLM(ctx, entry, systemPrompt, userPrompt, 1024)
	if err != nil {
		return nil, err
	}
	return parseAmendmentContent(extractContent(out))
}

// proposeG1AmendmentLocal — G1 정규식 개정안 제안을 proxy-local 에서 생성.
func (s *Server) proposeG1AmendmentLocal(ctx context.Context, orgClient *orgserver.Client, orgID string) (*localAmendmentProposal, error) {
	entry, err := s.selectAmendmentLLM(ctx)
	if err != nil {
		return nil, err
	}
	policy, err := orgClient.GetPolicy(orgID)
	if err != nil {
		return nil, fmt.Errorf("get policy: %w", err)
	}
	_, g1Patterns := guardrailContextFromPolicy(policy)

	g1Str := ""
	if len(g1Patterns) > 0 {
		var sb strings.Builder
		sb.WriteString("Current G1 patterns:\n")
		for _, p := range g1Patterns {
			pattern, _ := p["pattern"].(string)
			desc, _ := p["description"].(string)
			mode, _ := p["mode"].(string)
			sb.WriteString(fmt.Sprintf("- pattern=%q desc=%q mode=%s\n", pattern, desc, mode))
		}
		g1Str = sb.String()
	}

	trainingLog, _ := orgClient.GetTrainingLog(orgID)
	wikiContext := formatRecentDecisions(trainingLog, 100)

	systemPrompt := fmt.Sprintf(
		"You are the BoanClaw G1 Pattern Advisor.\n"+
			"G1 patterns are regex rules that detect/redact sensitive data (credentials, phone numbers, etc).\n\n"+
			"%s\n"+
			"%s\n"+
			"Based on patterns in recent HITL decisions, suggest NEW G1 regex patterns to add.\n"+
			"Focus on: data that was repeatedly blocked/approved → should become automatic G1 rules.\n"+
			"Return strict JSON: {\"diff\":\"list of new patterns as: +pattern | description | mode(credential/block)\",\"reasoning\":\"why these patterns are needed\"}",
		g1Str, wikiContext,
	)
	userPrompt := "Propose new G1 regex patterns based on accumulated wiki knowledge."

	out, err := s.callRegistryLLM(ctx, entry, systemPrompt, userPrompt, 1024)
	if err != nil {
		return nil, err
	}
	return parseAmendmentContent(extractContent(out))
}
