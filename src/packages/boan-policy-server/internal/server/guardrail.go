package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/samsung-sds/boanclaw/boan-policy-server/internal/policy"
)

type GuardrailEvaluateRequest struct {
	Text        string `json:"text"`
	Mode        string `json:"mode,omitempty"`
	UserEmail   string `json:"user_email,omitempty"`
	AccessLevel string `json:"access_level,omitempty"`
}

type GuardrailEvaluateResponse struct {
	Decision   string  `json:"decision"`
	Reason     string  `json:"reason"`
	Confidence float64 `json:"confidence"`
	Tier       int     `json:"tier,omitempty"`
	Response   string  `json:"response,omitempty"`
}

type GuardrailEvaluator struct {
	llmURL   string
	llmModel string
	llmKey   string
	client   *http.Client
}

func NewGuardrailEvaluator(llmURL, llmModel, llmKey string) *GuardrailEvaluator {
	return &GuardrailEvaluator{
		llmURL:   strings.TrimSpace(llmURL),
		llmModel: strings.TrimSpace(llmModel),
		llmKey:   strings.TrimSpace(llmKey),
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

var (
	guardrailBlockPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)\b`),
		regexp.MustCompile(`(?i)\b(?:주민등록|개인정보|민감정보|customer data|credentials?)\b`),
		regexp.MustCompile(`(?i)\b(?:exfiltrat|bypass|steal|dump|rm\s+-rf|drop database|delete production)\b`),
	}
	guardrailSuspiciousPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(?:internal|confidential|사내|내부|비공개|고객|client list|employee data)\b`),
		regexp.MustCompile(`(?i)\b(?:upload|share|send outside|외부 전송|붙여넣기|copy this|export)\b`),
		regexp.MustCompile(`(?i)\b(?:ssh|kubectl|terraform|gcloud|aws|az)\b`),
	}
)

func (s *Server) evaluateGuardrail(w http.ResponseWriter, r *http.Request, orgID string) {
	w.Header().Set("Content-Type", "application/json")

	var body GuardrailEvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	p, err := s.store.EnsureDefault(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := s.guardrail.Evaluate(r.Context(), p.Guardrail, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	json.NewEncoder(w).Encode(resp)
}

func (e *GuardrailEvaluator) Evaluate(ctx context.Context, cfg policy.GuardrailConfig, req GuardrailEvaluateRequest) (GuardrailEvaluateResponse, error) {
	text := strings.TrimSpace(req.Text)
	if text == "" {
		return GuardrailEvaluateResponse{
			Decision:   "block",
			Reason:     "empty text",
			Confidence: 1,
		}, nil
	}

	if e.llmURL != "" && e.llmModel != "" {
		if resp, err := e.evaluateWithLLM(ctx, cfg, req); err == nil && isValidGuardrailDecision(resp.Decision) {
			return resp, nil
		}
	}

	return evaluateGuardrailHeuristic(cfg, req), nil
}

func (e *GuardrailEvaluator) evaluateWithLLM(ctx context.Context, cfg policy.GuardrailConfig, req GuardrailEvaluateRequest) (GuardrailEvaluateResponse, error) {
	systemPrompt := fmt.Sprintf(
		"You are an S4 guardrail server. Evaluate the user's request against the constitution and provide both a safety decision and an appropriate response.\n"+
			"Constitution:\n%s\n\n"+
			"Return strict JSON only: {\"decision\":\"allow|ask|block\",\"reason\":\"short reason\",\"confidence\":0.0,\"response\":\"your answer to the user's question if allowed, or empty if blocked\"}",
		strings.TrimSpace(cfg.Constitution),
	)
	payload := map[string]any{
		"model": e.llmModel,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": fmt.Sprintf("mode=%s\ntext=%s", req.Mode, req.Text)},
		},
		"temperature": 0,
		"stream":      false,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return GuardrailEvaluateResponse{}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.llmURL, bytes.NewReader(raw))
	if err != nil {
		return GuardrailEvaluateResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if e.llmKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+e.llmKey)
	}

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return GuardrailEvaluateResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return GuardrailEvaluateResponse{}, fmt.Errorf("guardrail llm returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var upstream struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&upstream); err != nil {
		return GuardrailEvaluateResponse{}, err
	}
	content := ""
	if len(upstream.Choices) > 0 {
		content = strings.TrimSpace(upstream.Choices[0].Message.Content)
	}
	if content == "" {
		content = strings.TrimSpace(upstream.Message.Content)
	}
	if content == "" {
		content = strings.TrimSpace(upstream.Response)
	}
	if content == "" {
		return GuardrailEvaluateResponse{}, fmt.Errorf("guardrail llm returned no content")
	}

	var parsed GuardrailEvaluateResponse
	if err := decodeLooseJSON(content, &parsed); err != nil {
		return GuardrailEvaluateResponse{}, err
	}
	parsed.Decision = strings.ToLower(strings.TrimSpace(parsed.Decision))
	if parsed.Confidence < 0 || parsed.Confidence > 1 || math.IsNaN(parsed.Confidence) {
		parsed.Confidence = 0.5
	}
	if parsed.Reason == "" {
		parsed.Reason = "llm classified request"
	}
	parsed.Tier = 1
	return parsed, nil
}

func evaluateGuardrailHeuristic(cfg policy.GuardrailConfig, req GuardrailEvaluateRequest) GuardrailEvaluateResponse {
	text := strings.ToLower(strings.TrimSpace(req.Text))
	constitution := strings.ToLower(strings.TrimSpace(cfg.Constitution))

	for _, pattern := range guardrailBlockPatterns {
		if pattern.MatchString(text) {
			return GuardrailEvaluateResponse{Decision: "block", Reason: "critical guardrail blocked credential or critical data pattern", Confidence: 0.98}
		}
	}
	for _, keyword := range extractGuardrailKeywords(constitution, "block") {
		if strings.Contains(text, keyword) {
			return GuardrailEvaluateResponse{Decision: "block", Reason: "blocked by critical guardrail constitution", Confidence: 0.9}
		}
	}
	for _, pattern := range guardrailSuspiciousPatterns {
		if pattern.MatchString(text) {
			return GuardrailEvaluateResponse{Decision: "ask", Reason: "critical guardrail flagged content requiring human review", Confidence: 0.75}
		}
	}
	for _, keyword := range extractGuardrailKeywords(constitution, "ask") {
		if strings.Contains(text, keyword) {
			return GuardrailEvaluateResponse{Decision: "ask", Reason: "requires human review per critical guardrail constitution", Confidence: 0.7}
		}
	}
	return GuardrailEvaluateResponse{Decision: "allow", Reason: "no critical guardrail concern detected", Confidence: 0.85}
}

func extractGuardrailKeywords(constitution, mode string) []string {
	if constitution == "" {
		return nil
	}
	lines := strings.Split(constitution, "\n")
	var keywords []string
	for _, line := range lines {
		lower := strings.ToLower(strings.TrimSpace(line))
		if lower == "" {
			continue
		}
		switch mode {
		case "block":
			if !strings.Contains(lower, "차단") && !strings.Contains(lower, "금지") && !strings.Contains(lower, "block") && !strings.Contains(lower, "deny") && !strings.Contains(lower, "절대") {
				continue
			}
		case "ask":
			if !strings.Contains(lower, "의심") && !strings.Contains(lower, "검토") && !strings.Contains(lower, "승인") && !strings.Contains(lower, "review") && !strings.Contains(lower, "suspicious") && !strings.Contains(lower, "ask") {
				continue
			}
		}
		for _, token := range regexp.MustCompile(`[a-z0-9가-힣._-]{3,}`).FindAllString(lower, -1) {
			switch token {
			case "block", "deny", "review", "suspicious", "ask", "차단", "금지", "검토", "승인", "절대":
				continue
			}
			keywords = append(keywords, token)
		}
	}
	return keywords
}

func decodeLooseJSON(raw string, target any) error {
	if err := json.Unmarshal([]byte(raw), target); err == nil {
		return nil
	}
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start < 0 || end <= start {
		return fmt.Errorf("no json object found")
	}
	return json.Unmarshal([]byte(raw[start:end+1]), target)
}

func isValidGuardrailDecision(decision string) bool {
	switch decision {
	case "allow", "ask", "block":
		return true
	default:
		return false
	}
}

// ── Auto-judge (HITL 자동 판단 에이전트) ─────────────────────────────────────

// HITLDecision is one entry in the JSONL training log / LLM wiki.
type HITLDecision struct {
	Timestamp  string  `json:"timestamp"`
	OrgID      string  `json:"org_id"`
	Text       string  `json:"text"`
	Mode       string  `json:"mode"`
	Reason     string  `json:"flagged_reason"`
	Decision   string  `json:"decision"` // "approve" or "reject"
	Reasoning  string  `json:"reasoning"`
	Confidence float64 `json:"confidence"`
	Source     string  `json:"source"` // "auto" or "human"
}

// HITLTrainingLog is a thread-safe append-only JSONL log that doubles as the
// LLM wiki: recent entries are included as few-shot examples when auto-judging.
type HITLTrainingLog struct {
	mu   sync.Mutex
	path string
}

func NewHITLTrainingLog(path string) *HITLTrainingLog {
	return &HITLTrainingLog{path: path}
}

func (l *HITLTrainingLog) Append(d HITLDecision) {
	if l.path == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	raw, _ := json.Marshal(d)
	f.Write(append(raw, '\n'))
}

// Recent returns the last n decisions from the log, oldest-first.
func (l *HITLTrainingLog) Recent(n int) []HITLDecision {
	if l.path == "" || n <= 0 {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var all []HITLDecision
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var d HITLDecision
		if json.Unmarshal(sc.Bytes(), &d) == nil {
			all = append(all, d)
		}
	}
	if len(all) <= n {
		return all
	}
	return all[len(all)-n:]
}

// AutoJudgeRequest is sent to POST /org/{id}/v1/guardrail/auto-judge.
type AutoJudgeRequest struct {
	Text   string `json:"text"`
	Mode   string `json:"mode,omitempty"`
	Reason string `json:"reason"`
}

// AutoJudgeResponse is returned by the auto-judge endpoint.
type AutoJudgeResponse struct {
	Decision   string  `json:"decision"`  // "approve" or "reject"
	Reasoning  string  `json:"reasoning"`
	Confidence float64 `json:"confidence"`
}

// AutoJudge calls the LLM (falling back to heuristic) with the accumulated
// wiki as few-shot examples and returns an approve/reject decision.
func (e *GuardrailEvaluator) AutoJudge(ctx context.Context, cfg policy.GuardrailConfig, log *HITLTrainingLog, orgID string, req AutoJudgeRequest) (AutoJudgeResponse, error) {
	// Build few-shot wiki from recent decisions.
	var wikiLines []string
	if log != nil {
		for _, d := range log.Recent(10) {
			wikiLines = append(wikiLines, fmt.Sprintf("- %q flagged=%q → %s (%s)", d.Text, d.Reason, d.Decision, d.Reasoning))
		}
	}
	wiki := ""
	if len(wikiLines) > 0 {
		wiki = "## Past decisions (LLM wiki)\n" + strings.Join(wikiLines, "\n") + "\n\n"
	}

	if e.llmURL != "" && e.llmModel != "" {
		if resp, err := e.autoJudgeWithLLM(ctx, cfg, wiki, req); err == nil {
			return resp, nil
		}
	}
	return e.autoJudgeHeuristic(cfg, req), nil
}

func (e *GuardrailEvaluator) autoJudgeWithLLM(ctx context.Context, cfg policy.GuardrailConfig, wiki string, req AutoJudgeRequest) (AutoJudgeResponse, error) {
	systemPrompt := fmt.Sprintf(
		"You are a BoanClaw HITL auto-judge agent. Your job is to approve or reject flagged inputs.\n\nConstitution:\n%s\n\n%sReturn strict JSON only: {\"decision\":\"approve|reject\",\"reasoning\":\"short reason\",\"confidence\":0.0}.",
		strings.TrimSpace(cfg.Constitution),
		wiki,
	)
	payload := map[string]any{
		"model": e.llmModel,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": fmt.Sprintf("mode=%s\nflagged_reason=%s\ntext=%s", req.Mode, req.Reason, req.Text)},
		},
		"temperature": 0,
		"stream":      false,
	}
	raw, _ := json.Marshal(payload)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.llmURL, bytes.NewReader(raw))
	if err != nil {
		return AutoJudgeResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if e.llmKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+e.llmKey)
	}
	resp, err := e.client.Do(httpReq)
	if err != nil {
		return AutoJudgeResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return AutoJudgeResponse{}, fmt.Errorf("llm returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var upstream struct {
		Choices []struct {
			Message struct{ Content string `json:"content"` } `json:"message"`
		} `json:"choices"`
		Message struct{ Content string `json:"content"` } `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&upstream); err != nil {
		return AutoJudgeResponse{}, err
	}
	content := ""
	if len(upstream.Choices) > 0 {
		content = strings.TrimSpace(upstream.Choices[0].Message.Content)
	}
	if content == "" {
		content = strings.TrimSpace(upstream.Message.Content)
	}
	if content == "" {
		return AutoJudgeResponse{}, fmt.Errorf("no content")
	}
	var parsed AutoJudgeResponse
	if err := decodeLooseJSON(content, &parsed); err != nil {
		return AutoJudgeResponse{}, err
	}
	parsed.Decision = strings.ToLower(strings.TrimSpace(parsed.Decision))
	if parsed.Decision != "approve" && parsed.Decision != "reject" {
		return AutoJudgeResponse{}, fmt.Errorf("invalid decision: %q", parsed.Decision)
	}
	if parsed.Confidence < 0 || parsed.Confidence > 1 || math.IsNaN(parsed.Confidence) {
		parsed.Confidence = 0.5
	}
	return parsed, nil
}

func (e *GuardrailEvaluator) autoJudgeHeuristic(cfg policy.GuardrailConfig, req AutoJudgeRequest) AutoJudgeResponse {
	// Reuse guardrail heuristic: block → reject, ask → reject-by-default, allow → approve.
	gr := evaluateGuardrailHeuristic(cfg, GuardrailEvaluateRequest{Text: req.Text, Mode: req.Mode})
	switch gr.Decision {
	case "block":
		return AutoJudgeResponse{Decision: "reject", Reasoning: gr.Reason, Confidence: gr.Confidence}
	case "ask":
		return AutoJudgeResponse{Decision: "reject", Reasoning: "heuristic flagged as suspicious; defaulting to reject", Confidence: 0.6}
	default:
		return AutoJudgeResponse{Decision: "approve", Reasoning: gr.Reason, Confidence: gr.Confidence}
	}
}

// ── Tier 2: Wiki Guardrail ──────────────────────────────────────────────────

func (s *Server) wikiEvaluateGuardrail(w http.ResponseWriter, r *http.Request, orgID string) {
	w.Header().Set("Content-Type", "application/json")

	var body GuardrailEvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	p, err := s.store.EnsureDefault(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := s.wikiGuardrail.WikiEvaluate(r.Context(), p.Guardrail, s.trainingLog, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	json.NewEncoder(w).Encode(resp)
}

// WikiEvaluate — Tier 2 평가: training log(wiki)를 few-shot context로 포함하여 LLM 평가
func (e *GuardrailEvaluator) WikiEvaluate(ctx context.Context, cfg policy.GuardrailConfig, log *HITLTrainingLog, req GuardrailEvaluateRequest) (GuardrailEvaluateResponse, error) {
	text := strings.TrimSpace(req.Text)
	if text == "" {
		return GuardrailEvaluateResponse{Decision: "block", Reason: "empty text", Confidence: 1, Tier: 2}, nil
	}

	// training log에서 최근 50건을 wiki context로 구성
	wikiContext := ""
	if log != nil {
		recent := log.Recent(50)
		if len(recent) > 0 {
			var sb strings.Builder
			sb.WriteString("Past decisions (wiki knowledge):\n")
			for _, d := range recent {
				sb.WriteString(fmt.Sprintf("- text=%q reason=%q → %s (confidence=%.2f, source=%s)\n",
					truncate(d.Text, 80), d.Reason, d.Decision, d.Confidence, d.Source))
			}
			wikiContext = sb.String()
		}
	}

	if e.llmURL != "" && e.llmModel != "" {
		resp, err := e.wikiEvaluateWithLLM(ctx, cfg, wikiContext, req)
		if err == nil && isValidGuardrailDecision(resp.Decision) {
			return resp, nil
		}
	}

	// LLM 불가 시 heuristic fallback
	heuristic := evaluateGuardrailHeuristic(cfg, req)
	heuristic.Tier = 2
	return heuristic, nil
}

func (e *GuardrailEvaluator) wikiEvaluateWithLLM(ctx context.Context, cfg policy.GuardrailConfig, wikiContext string, req GuardrailEvaluateRequest) (GuardrailEvaluateResponse, error) {
	systemPrompt := fmt.Sprintf(
		"You are the BoanClaw Wiki Guardrail (Tier 2). Use accumulated knowledge from past decisions to evaluate this request.\n\n"+
			"Constitution:\n%s\n\n"+
			"%s\n"+
			"Evaluate the user's request. Return strict JSON only: {\"decision\":\"allow|ask|block\",\"reason\":\"short reason\",\"confidence\":0.0,\"response\":\"answer if allowed\"}",
		strings.TrimSpace(cfg.Constitution), wikiContext,
	)
	payload := map[string]any{
		"model": e.llmModel,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": fmt.Sprintf("mode=%s\ntext=%s", req.Mode, req.Text)},
		},
		"temperature": 0,
		"stream":      false,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return GuardrailEvaluateResponse{}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.llmURL, bytes.NewReader(raw))
	if err != nil {
		return GuardrailEvaluateResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if e.llmKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+e.llmKey)
	}

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return GuardrailEvaluateResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return GuardrailEvaluateResponse{}, fmt.Errorf("wiki llm returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var upstream struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&upstream); err != nil {
		return GuardrailEvaluateResponse{}, err
	}
	content := ""
	if len(upstream.Choices) > 0 {
		content = strings.TrimSpace(upstream.Choices[0].Message.Content)
	}
	if content == "" {
		content = strings.TrimSpace(upstream.Message.Content)
	}
	if content == "" {
		content = strings.TrimSpace(upstream.Response)
	}
	if content == "" {
		return GuardrailEvaluateResponse{}, fmt.Errorf("wiki llm returned no content")
	}

	var parsed GuardrailEvaluateResponse
	if err := decodeLooseJSON(content, &parsed); err != nil {
		return GuardrailEvaluateResponse{}, err
	}
	parsed.Decision = strings.ToLower(strings.TrimSpace(parsed.Decision))
	if parsed.Confidence < 0 || parsed.Confidence > 1 || math.IsNaN(parsed.Confidence) {
		parsed.Confidence = 0.5
	}
	if parsed.Reason == "" {
		parsed.Reason = "wiki guardrail classified request"
	}
	parsed.Tier = 2
	return parsed, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// ── Training Log 쓰기 엔드포인트 (인간 결정 피드백용) ─────────────────────────

func (s *Server) appendTrainingLog(w http.ResponseWriter, r *http.Request, orgID string) {
	var entry HITLDecision
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	entry.OrgID = orgID
	if entry.Source == "" {
		entry.Source = "human"
	}
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	s.trainingLog.Append(entry)
	w.WriteHeader(http.StatusNoContent)
}

// ── 헌법 개정 제안 ──────────────────────────────────────────────────────────

type AmendmentProposal struct {
	Diff       string `json:"diff"`
	Reasoning  string `json:"reasoning"`
	ProposedAt string `json:"proposed_at"`
}

func (s *Server) proposeAmendment(w http.ResponseWriter, r *http.Request, orgID string) {
	w.Header().Set("Content-Type", "application/json")

	p, err := s.store.EnsureDefault(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	proposal, err := s.wikiGuardrail.ProposeAmendment(r.Context(), p.Guardrail, s.trainingLog)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	json.NewEncoder(w).Encode(proposal)
}

// ProposeAmendment — training log 분석 → 헌법 개정안(diff) 생성
func (e *GuardrailEvaluator) ProposeAmendment(ctx context.Context, cfg policy.GuardrailConfig, log *HITLTrainingLog) (*AmendmentProposal, error) {
	if e.llmURL == "" || e.llmModel == "" {
		return nil, fmt.Errorf("wiki LLM not configured for amendment proposals")
	}

	// training log에서 최근 100건 분석
	wikiContext := ""
	if log != nil {
		recent := log.Recent(100)
		if len(recent) > 0 {
			var sb strings.Builder
			sb.WriteString("Recent guardrail decisions:\n")
			for _, d := range recent {
				sb.WriteString(fmt.Sprintf("- text=%q reason=%q → %s (source=%s)\n",
					truncate(d.Text, 60), d.Reason, d.Decision, d.Source))
			}
			wikiContext = sb.String()
		}
	}

	systemPrompt := fmt.Sprintf(
		"You are the BoanClaw Constitution Amendment Advisor.\n\n"+
			"Current constitution:\n%s\n\n"+
			"%s\n"+
			"Based on the pattern of recent decisions, propose amendments to the constitution.\n"+
			"Return strict JSON: {\"diff\":\"unified diff of the constitution (lines starting with + for additions, - for removals)\",\"reasoning\":\"why this amendment is needed\"}",
		strings.TrimSpace(cfg.Constitution), wikiContext,
	)
	payload := map[string]any{
		"model": e.llmModel,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": "Propose constitution amendments based on the accumulated wiki knowledge."},
		},
		"temperature": 0,
		"stream":      false,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.llmURL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if e.llmKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+e.llmKey)
	}

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("amendment llm returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var upstream struct {
		Choices []struct {
			Message struct{ Content string `json:"content"` } `json:"message"`
		} `json:"choices"`
		Message  struct{ Content string `json:"content"` } `json:"message"`
		Response string                                     `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&upstream); err != nil {
		return nil, err
	}
	content := ""
	if len(upstream.Choices) > 0 {
		content = strings.TrimSpace(upstream.Choices[0].Message.Content)
	}
	if content == "" {
		content = strings.TrimSpace(upstream.Message.Content)
	}
	if content == "" {
		content = strings.TrimSpace(upstream.Response)
	}
	if content == "" {
		return nil, fmt.Errorf("amendment llm returned no content")
	}

	var parsed AmendmentProposal
	if err := decodeLooseJSON(content, &parsed); err != nil {
		return nil, err
	}
	parsed.ProposedAt = time.Now().UTC().Format(time.RFC3339)
	return &parsed, nil
}
