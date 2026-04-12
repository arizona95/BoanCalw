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
	LLMURL      string `json:"llm_url,omitempty"`   // proxy가 전달한 security LLM URL
	LLMModel    string `json:"llm_model,omitempty"` // proxy가 전달한 security LLM model
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
		client:   &http.Client{Timeout: 30 * time.Second},
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

	// LLM 선택 우선순위: 요청에 포함된 registry LLM > 정책 설정 > env 변수
	evaluator := s.guardrail
	if body.LLMURL != "" {
		evaluator = NewGuardrailEvaluator(body.LLMURL, body.LLMModel, s.cfg.GuardrailLLMKey)
	} else if p.Guardrail.LLMURL != "" {
		evaluator = NewGuardrailEvaluator(p.Guardrail.LLMURL, p.Guardrail.LLMModel, s.cfg.GuardrailLLMKey)
	}
	resp, err := evaluator.Evaluate(r.Context(), p.Guardrail, body)
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
		resp, err := e.evaluateWithLLM(ctx, cfg, req)
		if err == nil && isValidGuardrailDecision(resp.Decision) {
			return resp, nil
		}
		// LLM 실패 → fail-closed (heuristic fallback 하지 않음)
		return GuardrailEvaluateResponse{
			Decision:   "block",
			Reason:     fmt.Sprintf("guardrail LLM failed — fail-closed: %v", err),
			Confidence: 1,
			Tier:       1,
		}, nil
	}

	// LLM 미설정 → heuristic만 사용 (credential 패턴 등 기본 검사)
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

	// LLM 선택 우선순위: 요청에 포함된 registry LLM > 정책 설정 > env 변수
	wikiEval := s.wikiGuardrail
	if body.LLMURL != "" {
		wikiEval = NewGuardrailEvaluator(body.LLMURL, body.LLMModel, s.cfg.WikiLLMKey)
	} else if p.Guardrail.WikiLLMURL != "" {
		wikiEval = NewGuardrailEvaluator(p.Guardrail.WikiLLMURL, p.Guardrail.WikiLLMModel, s.cfg.WikiLLMKey)
	}
	resp, err := wikiEval.WikiEvaluateWithStore(r.Context(), p.Guardrail, s.trainingLog, s.wikiStore, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	json.NewEncoder(w).Encode(resp)
}

// WikiEvaluate — Tier 2 평가: compiled wiki context 우선, fallback으로 raw entries 사용
func (e *GuardrailEvaluator) WikiEvaluate(ctx context.Context, cfg policy.GuardrailConfig, log *HITLTrainingLog, req GuardrailEvaluateRequest) (GuardrailEvaluateResponse, error) {
	return e.WikiEvaluateWithStore(ctx, cfg, log, nil, req)
}

// WikiEvaluateWithStore — WikiStore가 있으면 compiled wiki context를 사용
func (e *GuardrailEvaluator) WikiEvaluateWithStore(ctx context.Context, cfg policy.GuardrailConfig, log *HITLTrainingLog, ws *WikiStore, req GuardrailEvaluateRequest) (GuardrailEvaluateResponse, error) {
	text := strings.TrimSpace(req.Text)
	if text == "" {
		return GuardrailEvaluateResponse{Decision: "block", Reason: "empty text", Confidence: 1, Tier: 2}, nil
	}

	// Try compiled wiki context first
	wikiContext := ""
	if ws != nil {
		wikiContext = ws.GetContext()
	}

	// If compiled wiki is empty/not available, fall back to raw entries
	if wikiContext == "" && log != nil {
		recent := log.Recent(50)
		if len(recent) > 0 {
			var sb strings.Builder
			sb.WriteString("Past decisions (wiki knowledge):\n")
			for _, d := range recent {
				sb.WriteString(fmt.Sprintf("- text=%q reason=%q -> %s (confidence=%.2f, source=%s)\n",
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

// ProposeG1Amendment — training log 분석 → G1 정규식 패턴 추가/수정 제안
func (e *GuardrailEvaluator) ProposeG1Amendment(ctx context.Context, cfg policy.GuardrailConfig, log *HITLTrainingLog) (*AmendmentProposal, error) {
	if e.llmURL == "" || e.llmModel == "" {
		return nil, fmt.Errorf("wiki LLM not configured for G1 amendment proposals")
	}

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

	// Current G1 patterns
	g1Patterns := ""
	if len(cfg.G1CustomPatterns) > 0 {
		var sb strings.Builder
		sb.WriteString("Current G1 patterns:\n")
		for _, p := range cfg.G1CustomPatterns {
			sb.WriteString(fmt.Sprintf("- pattern=%q desc=%q mode=%s\n", p.Pattern, p.Description, p.Mode))
		}
		g1Patterns = sb.String()
	}

	systemPrompt := fmt.Sprintf(
		"You are the BoanClaw G1 Pattern Advisor.\n"+
			"G1 patterns are regex rules that detect/redact sensitive data (credentials, phone numbers, etc).\n\n"+
			"%s\n"+
			"%s\n"+
			"Based on patterns in recent HITL decisions, suggest NEW G1 regex patterns to add.\n"+
			"Focus on: data that was repeatedly blocked/approved → should become automatic G1 rules.\n"+
			"Return strict JSON: {\"diff\":\"list of new patterns as: +pattern | description | mode(credential/block)\",\"reasoning\":\"why these patterns are needed\"}",
		g1Patterns, wikiContext,
	)
	payload := map[string]any{
		"model": e.llmModel,
		"messages": []map[string]string{
			{"role": "system", "content": systemPrompt},
			{"role": "user", "content": "Propose new G1 regex patterns based on accumulated wiki knowledge."},
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
		return nil, fmt.Errorf("G1 amendment llm returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
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
		return nil, fmt.Errorf("G1 amendment llm returned no content")
	}

	var parsed AmendmentProposal
	if err := decodeLooseJSON(content, &parsed); err != nil {
		return nil, err
	}
	parsed.ProposedAt = time.Now().UTC().Format(time.RFC3339)
	return &parsed, nil
}

// ── WikiStore: Karpathy-pattern wiki storage ────────────────────────────────

// WikiPageInfo describes a single wiki page on disk.
type WikiPageInfo struct {
	Path      string `json:"path"`
	Title     string `json:"title"`
	UpdatedAt string `json:"updated_at"`
	Size      int64  `json:"size"`
}

// WikiStore manages compiled wiki markdown pages on disk.
type WikiStore struct {
	mu      sync.RWMutex
	baseDir string // e.g. /data/policies/wiki
}

func NewWikiStore(dataDir string) *WikiStore {
	dir := dataDir + "/wiki"
	os.MkdirAll(dir, 0755)
	os.MkdirAll(dir+"/patterns", 0755)
	os.MkdirAll(dir+"/proposals", 0755)
	return &WikiStore{baseDir: dir}
}

// GetIndex returns the content of index.md.
func (ws *WikiStore) GetIndex() (string, error) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	data, err := os.ReadFile(ws.baseDir + "/index.md")
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return string(data), nil
}

// GetPage returns the content of a specific wiki page by relative path.
func (ws *WikiStore) GetPage(relPath string) (string, error) {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	// Sanitize path to prevent traversal
	clean := strings.ReplaceAll(relPath, "..", "")
	clean = strings.TrimPrefix(clean, "/")
	if clean == "" {
		return "", fmt.Errorf("empty path")
	}
	data, err := os.ReadFile(ws.baseDir + "/" + clean)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("page not found: %s", relPath)
		}
		return "", err
	}
	return string(data), nil
}

// ListPages returns metadata for all wiki files.
func (ws *WikiStore) ListPages() []WikiPageInfo {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	var pages []WikiPageInfo
	wikiWalkDir(ws.baseDir, ws.baseDir, &pages)
	return pages
}

func wikiWalkDir(root, dir string, out *[]WikiPageInfo) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		full := dir + "/" + e.Name()
		if e.IsDir() {
			wikiWalkDir(root, full, out)
			continue
		}
		if !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		rel := strings.TrimPrefix(full, root+"/")
		info, _ := e.Info()
		var modTime string
		var size int64
		if info != nil {
			modTime = info.ModTime().UTC().Format(time.RFC3339)
			size = info.Size()
		}
		title := strings.TrimSuffix(e.Name(), ".md")
		*out = append(*out, WikiPageInfo{
			Path:      rel,
			Title:     title,
			UpdatedAt: modTime,
			Size:      size,
		})
	}
}

// GetContext returns the compiled wiki as a short context string for G3 evaluation.
func (ws *WikiStore) GetContext() string {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	var sb strings.Builder
	// Include overview.md if present
	if data, err := os.ReadFile(ws.baseDir + "/overview.md"); err == nil {
		content := strings.TrimSpace(string(data))
		if content != "" {
			sb.WriteString("## Security Overview\n")
			sb.WriteString(content)
			sb.WriteString("\n\n")
		}
	}
	// Include pattern files
	patternEntries, _ := os.ReadDir(ws.baseDir + "/patterns")
	for _, e := range patternEntries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		if data, err := os.ReadFile(ws.baseDir + "/patterns/" + e.Name()); err == nil {
			content := strings.TrimSpace(string(data))
			if content != "" {
				sb.WriteString(content)
				sb.WriteString("\n\n")
			}
		}
	}
	return sb.String()
}

// Compile reads all raw HITL entries and uses an LLM to generate/update wiki pages.
func (ws *WikiStore) Compile(ctx context.Context, llmURL, llmModel, llmKey string, log *HITLTrainingLog, cfg policy.GuardrailConfig) error {
	if llmURL == "" || llmModel == "" {
		return fmt.Errorf("wiki LLM not configured for compilation")
	}

	// Read ALL training log entries
	entries := log.Recent(10000) // effectively all
	if len(entries) == 0 {
		return fmt.Errorf("no training log entries to compile")
	}

	// Build training log summary
	var entrySummary strings.Builder
	entrySummary.WriteString(fmt.Sprintf("Total HITL decisions: %d\n\n", len(entries)))
	// Stats
	humanCount, autoCount, approveCount, rejectCount := 0, 0, 0, 0
	reasonCounts := map[string]int{}
	for _, d := range entries {
		if d.Source == "human" {
			humanCount++
		} else {
			autoCount++
		}
		if d.Decision == "approve" {
			approveCount++
		} else {
			rejectCount++
		}
		if d.Reason != "" {
			reasonCounts[d.Reason]++
		}
	}
	entrySummary.WriteString(fmt.Sprintf("Human decisions: %d, Auto decisions: %d\n", humanCount, autoCount))
	entrySummary.WriteString(fmt.Sprintf("Approvals: %d, Rejections: %d\n\n", approveCount, rejectCount))

	// Include recent entries as examples (max 50)
	exampleCount := len(entries)
	if exampleCount > 50 {
		exampleCount = 50
	}
	entrySummary.WriteString("Recent decisions:\n")
	for _, d := range entries[len(entries)-exampleCount:] {
		entrySummary.WriteString(fmt.Sprintf("- [%s] %s: text=%q reason=%q -> %s (confidence=%.2f, source=%s)\n",
			d.Timestamp, d.Mode, truncate(d.Text, 60), d.Reason, d.Decision, d.Confidence, d.Source))
	}

	// Top reasons
	entrySummary.WriteString("\nTop flagged reasons:\n")
	for reason, count := range reasonCounts {
		entrySummary.WriteString(fmt.Sprintf("- %q: %d times\n", reason, count))
	}

	client := &http.Client{Timeout: 120 * time.Second}

	callLLM := func(systemPrompt, userPrompt string) (string, error) {
		payload := map[string]any{
			"model": llmModel,
			"messages": []map[string]string{
				{"role": "system", "content": systemPrompt},
				{"role": "user", "content": userPrompt},
			},
			"temperature": 0,
			"stream":      false,
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return "", err
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, llmURL, bytes.NewReader(raw))
		if err != nil {
			return "", err
		}
		httpReq.Header.Set("Content-Type", "application/json")
		if llmKey != "" {
			httpReq.Header.Set("Authorization", "Bearer "+llmKey)
		}
		resp, err := client.Do(httpReq)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			return "", fmt.Errorf("wiki compile LLM returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var upstream struct {
			Choices []struct {
				Message struct{ Content string `json:"content"` } `json:"message"`
			} `json:"choices"`
			Message  struct{ Content string `json:"content"` } `json:"message"`
			Response string                                     `json:"response"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&upstream); err != nil {
			return "", err
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
		return content, nil
	}

	ws.mu.Lock()
	defer ws.mu.Unlock()

	compiledAt := time.Now().UTC().Format(time.RFC3339)
	logData := entrySummary.String()

	// 1. Generate overview.md
	overviewContent, err := callLLM(
		"You are a security analyst for BoanClaw guardrail system. Analyze the HITL decision log and produce a concise security posture overview in markdown. "+
			"Include: overall threat profile, key trends, areas of concern, and recommendations. Keep it under 500 words. Output raw markdown only, no code fences.",
		fmt.Sprintf("Constitution:\n%s\n\nTraining log data:\n%s", strings.TrimSpace(cfg.Constitution), logData),
	)
	if err != nil {
		overviewContent = fmt.Sprintf("# Security Overview\n\nCompilation failed: %v\n\nStats: %d total, %d human, %d auto, %d approve, %d reject",
			err, len(entries), humanCount, autoCount, approveCount, rejectCount)
	}
	os.WriteFile(ws.baseDir+"/overview.md", []byte(overviewContent), 0644)

	// 2. Generate pattern pages
	patternsContent, err := callLLM(
		"You are a security analyst. Analyze the HITL decision log and identify distinct security PATTERNS (categories of blocked/approved content). "+
			"For each pattern, write a short markdown section with: pattern name, description, frequency, typical decision, and examples. "+
			"Separate each pattern with '---PATTERN_BREAK---'. Output raw markdown, no code fences.",
		fmt.Sprintf("Training log data:\n%s", logData),
	)
	if err == nil && patternsContent != "" {
		// Split into individual pattern pages
		patternSections := strings.Split(patternsContent, "---PATTERN_BREAK---")
		for i, section := range patternSections {
			section = strings.TrimSpace(section)
			if section == "" {
				continue
			}
			// Extract title from first heading or use index
			name := fmt.Sprintf("pattern-%d", i+1)
			lines := strings.SplitN(section, "\n", 2)
			if len(lines) > 0 {
				heading := strings.TrimSpace(strings.TrimLeft(lines[0], "#"))
				if heading != "" {
					// Sanitize for filename
					safeName := strings.ToLower(heading)
					safeName = strings.Map(func(r rune) rune {
						if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
							return r
						}
						if r == ' ' || r == '_' {
							return '-'
						}
						return -1
					}, safeName)
					if len(safeName) > 50 {
						safeName = safeName[:50]
					}
					if safeName != "" {
						name = safeName
					}
				}
			}
			os.WriteFile(ws.baseDir+"/patterns/"+name+".md", []byte(section), 0644)
		}
	}

	// 3. Generate G1 change suggestions
	g1Content, err := callLLM(
		"You are a regex security advisor. Analyze the HITL decision log and current G1 patterns. "+
			"Suggest specific regex pattern additions/changes for the G1 layer. "+
			"Output markdown with each suggestion as a bullet point including the regex, description, and mode (credential/block). No code fences.",
		fmt.Sprintf("Current G1 patterns:\n%s\n\nTraining log data:\n%s",
			func() string {
				var sb strings.Builder
				for _, p := range cfg.G1CustomPatterns {
					sb.WriteString(fmt.Sprintf("- pattern=%q desc=%q mode=%s\n", p.Pattern, p.Description, p.Mode))
				}
				return sb.String()
			}(), logData),
	)
	if err == nil && g1Content != "" {
		os.WriteFile(ws.baseDir+"/proposals/g1-changes.md", []byte(g1Content), 0644)
	}

	// 4. Generate G2 constitution suggestions
	g2Content, err := callLLM(
		"You are a constitution advisor for BoanClaw guardrail. Analyze the HITL decision log and current constitution. "+
			"Suggest specific amendments to the constitution to better handle observed patterns. "+
			"Output markdown with clear before/after suggestions. No code fences.",
		fmt.Sprintf("Current constitution:\n%s\n\nTraining log data:\n%s", strings.TrimSpace(cfg.Constitution), logData),
	)
	if err == nil && g2Content != "" {
		os.WriteFile(ws.baseDir+"/proposals/g2-changes.md", []byte(g2Content), 0644)
	}

	// 5. Write compilation log entry
	logEntry := fmt.Sprintf("## Compilation at %s\n\n- Entries processed: %d\n- Human: %d, Auto: %d\n- Approve: %d, Reject: %d\n\n---\n\n",
		compiledAt, len(entries), humanCount, autoCount, approveCount, rejectCount)
	// Append to log.md
	existingLog, _ := os.ReadFile(ws.baseDir + "/log.md")
	os.WriteFile(ws.baseDir+"/log.md", []byte(string(existingLog)+logEntry), 0644)

	// 6. Write index.md
	pages := []WikiPageInfo{}
	wikiWalkDir(ws.baseDir, ws.baseDir, &pages)
	var indexBuf strings.Builder
	indexBuf.WriteString(fmt.Sprintf("# BoanClaw Wiki\n\nLast compiled: %s\n\nEntries processed: %d\n\n## Pages\n\n", compiledAt, len(entries)))
	for _, p := range pages {
		if p.Path == "index.md" {
			continue
		}
		indexBuf.WriteString(fmt.Sprintf("- [%s](%s) -- updated %s\n", p.Title, p.Path, p.UpdatedAt))
	}
	os.WriteFile(ws.baseDir+"/index.md", []byte(indexBuf.String()), 0644)

	return nil
}
