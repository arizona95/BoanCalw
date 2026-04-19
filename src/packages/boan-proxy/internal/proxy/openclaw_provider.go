package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/credential"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/devicekey"
)

// deviceJWTAudience — value the receiver validates against the JWT aud claim.
// Kept here (not in a shared constants package) to keep the dispatch path
// self-contained.
const deviceJWTAudience = "boan-org-cloud"
const deviceJWTTTL = 5 * time.Minute

var _ = devicekey.Identity{}

type registryLLM struct {
	Name              string `json:"name"`
	Endpoint          string   `json:"endpoint"`
	Type              string   `json:"type"`
	CurlTemplate      string   `json:"curl_template"`
	ImageCurlTemplate string   `json:"image_curl_template"`
	Roles             []string `json:"roles"`
	IsSecurityLLM     bool     `json:"is_security_llm"`
	IsSecurityLMM     bool     `json:"is_security_lmm"`
	Healthy           bool     `json:"healthy"`
}

func (e *registryLLM) hasRole(role string) bool {
	for _, r := range e.Roles {
		if r == role {
			return true
		}
	}
	// 하위 호환
	if e.IsSecurityLLM && (role == "chat" || role == "g2") {
		return true
	}
	if e.IsSecurityLMM && role == "vision" {
		return true
	}
	return false
}

type openClawConfigResponse struct {
	BaseURL   string `json:"base_url"`
	ModelID   string `json:"model_id"`
	ModelName string `json:"model_name"`
	Provider  string `json:"provider"`
}

var (
	curlHeaderRe     = regexp.MustCompile(`(?m)-H\s+['"]?([^:'"]+):\s*([^'"\n]+)['"]?`)
	curlURLRe        = regexp.MustCompile(`https?://[^\s'"\\]+`)
	curlDataSingleRe = regexp.MustCompile(`(?s)(?:--data-raw|-d)\s+'([^']*)'`)
	curlDataDoubleRe = regexp.MustCompile(`(?s)(?:--data-raw|-d)\s+"([^"]*)"`)
	curlModelRe      = regexp.MustCompile(`"model"\s*:\s*"([^"]+)"`)
	credRefRe        = regexp.MustCompile(`\{\{CREDENTIAL:([^}]+)\}\}`)
	credentialReadablePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)\b(?:ghp|github_pat|sk-[a-z0-9]|AKIA|AIza)[A-Za-z0-9_\-]{8,}\b`),
		regexp.MustCompile(`(?i)\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`),
		regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*\S+`),
		regexp.MustCompile(`(?i)\b(?:setx?|export)\s+[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY)[A-Z0-9_]*\s*[= ]\s*\S+`),
	}
)

func sanitizeCredentialReadableText(text string) string {
	return sanitizeCredentialReadableTextWithKnown(text, nil, nil)
}

// redactValueInKeywordMatch preserves the "keyword:" or "keyword=" part of a
// credential pattern match (e.g. "api-key: VALUE") and replaces only the value
// portion with [REDACTED], keeping header names and variable names intact.
func redactValueInKeywordMatch(match string) string {
	if isObviouslyNonSecretCredential(match) {
		return match
	}
	if strings.Contains(match, "__BOAN_PASS_THRU_") {
		return match
	}
	// Find the last ':' or '=' — the value follows this separator.
	lastSep := -1
	for i, ch := range match {
		if ch == ':' || ch == '=' {
			lastSep = i
		}
	}
	if lastSep < 0 {
		// Fallback: first space (handles "export VAR value" or "set VAR value").
		for i, ch := range match {
			if ch == ' ' || ch == '\t' {
				lastSep = i
				break
			}
		}
	}
	if lastSep < 0 {
		return "[REDACTED]"
	}
	j := lastSep + 1
	for j < len(match) && (match[j] == ' ' || match[j] == '\t') {
		j++
	}
	return match[:j] + "[REDACTED]"
}

func sanitizeCredentialReadableTextWithKnown(text string, known map[string]string, passthrough map[string]struct{}) string {
	if strings.TrimSpace(text) == "" {
		return text
	}
	protected := map[string]string{}
	sanitized := credRefRe.ReplaceAllStringFunc(text, func(match string) string {
		token := fmt.Sprintf("__BOAN_CRED_REF_%d__", len(protected)+1)
		protected[token] = match
		return token
	})
	if len(known) > 0 {
		values := make([]string, 0, len(known))
		for value := range known {
			if strings.TrimSpace(value) != "" {
				values = append(values, value)
			}
		}
		sort.Slice(values, func(i, j int) bool {
			return len(values[i]) > len(values[j])
		})
		for _, value := range values {
			sanitized = strings.ReplaceAll(sanitized, value, known[value])
		}
	}
	if len(passthrough) > 0 {
		values := make([]string, 0, len(passthrough))
		for value := range passthrough {
			if strings.TrimSpace(value) != "" {
				values = append(values, value)
			}
		}
		sort.Slice(values, func(i, j int) bool {
			return len(values[i]) > len(values[j])
		})
		for _, value := range values {
			token := fmt.Sprintf("__BOAN_PASS_THRU_%d__", len(protected)+1)
			protected[token] = value
			sanitized = strings.ReplaceAll(sanitized, value, token)
		}
	}
	for idx, pattern := range credentialReadablePatterns {
		// Patterns at index 3 and 4 match "keyword=value" form.
		// Preserve the keyword portion and only redact the value.
		valueOnly := idx >= 3
		sanitized = pattern.ReplaceAllStringFunc(sanitized, func(match string) string {
			if strings.Contains(match, "__BOAN_CRED_REF_") {
				return match
			}
			if strings.Contains(match, "__BOAN_PASS_THRU_") {
				return match
			}
			if isObviouslyNonSecretCredential(match) {
				return match
			}
			if valueOnly {
				return redactValueInKeywordMatch(match)
			}
			return "[REDACTED]"
		})
	}
	for token, original := range protected {
		sanitized = strings.ReplaceAll(sanitized, token, original)
	}
	return sanitized
}

func (s *Server) credentialPlaceholderMap(ctx context.Context, orgID string) map[string]string {
	if s == nil || s.cfg == nil || strings.TrimSpace(s.cfg.CredentialFilterURL) == "" || strings.TrimSpace(orgID) == "" {
		return nil
	}
	names := s.fetchCredentialNames(ctx, orgID)
	if len(names) == 0 {
		return nil
	}
	known := make(map[string]string, len(names))
	for _, name := range names {
		value, err := credential.Resolve(ctx, s.cfg.CredentialFilterURL, orgID, name)
		if err != nil || strings.TrimSpace(value) == "" {
			continue
		}
		known[value] = fmt.Sprintf("{{CREDENTIAL:%s}}", name)
	}
	if len(known) == 0 {
		return nil
	}
	return known
}

// loadLLMByRole — 역할별 LLM 조회 (g2, g3, chat, vision)
func (s *Server) loadLLMByRole(ctx context.Context, role string) (*registryLLM, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.cfg.LLMRegistryURL, "/")+"/llm/list", nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("registry returned %d", resp.StatusCode)
	}
	var entries []registryLLM
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.hasRole(role) {
			e := entry
			return &e, nil
		}
	}
	return nil, fmt.Errorf("no LLM bound to role %q", role)
}

// loadSelectedRegistryLLM — chat 용 LLM 선택.
// 우선순위: role="chat" 바인딩 → 레거시 IsSecurityLLM → 아무 healthy → 첫 entry.
func (s *Server) loadSelectedRegistryLLM(ctx context.Context) (*registryLLM, error) {
	// 1차: role="chat" 바인딩된 LLM (신규 role-based 경로)
	if entry, err := s.loadLLMByRole(ctx, "chat"); err == nil && entry != nil {
		return entry, nil
	}
	// Fallback: 등록된 전체 목록에서 legacy/healthy 기준으로 선택
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(s.cfg.LLMRegistryURL, "/")+"/llm/list", nil)
	if err != nil {
		return nil, err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("registry returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var entries []registryLLM
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no llm registered (LLM Registry 탭에서 chat 역할을 바인딩하세요)")
	}
	for _, entry := range entries {
		if entry.IsSecurityLLM {
			return &entry, nil
		}
	}
	for _, entry := range entries {
		if entry.Healthy {
			return &entry, nil
		}
	}
	return &entries[0], nil
}

func (s *Server) openClawConfig(ctx context.Context, baseURL string) (*openClawConfigResponse, error) {
	entry, err := s.loadSelectedRegistryLLM(ctx)
	if err != nil {
		return nil, err
	}
	return &openClawConfigResponse{
		BaseURL:   strings.TrimRight(baseURL, "/") + "/api/openclaw/v1",
		ModelID:   entry.Name,
		ModelName: entry.Name,
		Provider:  "boan",
	}, nil
}

func parseCurlTemplate(curlTemplate string) (method, endpoint string, headers map[string]string, body string) {
	method = http.MethodPost
	headers = map[string]string{}
	if m := curlURLRe.FindString(curlTemplate); m != "" {
		endpoint = m
	}
	for _, match := range curlHeaderRe.FindAllStringSubmatch(curlTemplate, -1) {
		if len(match) == 3 {
			headers[strings.TrimSpace(match[1])] = strings.TrimSpace(match[2])
		}
	}
	if m := curlDataSingleRe.FindStringSubmatch(curlTemplate); len(m) == 2 {
		body = m[1]
	} else if m := curlDataDoubleRe.FindStringSubmatch(curlTemplate); len(m) == 2 {
		body = m[1]
	}
	return method, endpoint, headers, body
}

func extractPromptFromMessages(rawMessages any) string {
	list, ok := rawMessages.([]any)
	if !ok {
		return ""
	}
	// 마지막 유저 메시지만 추출 — 태그 기반 라우팅([gcp_send] 등)의 정확도를 위해
	for i := len(list) - 1; i >= 0; i-- {
		msg, ok := list[i].(map[string]any)
		if !ok {
			continue
		}
		if role, _ := msg["role"].(string); role != "user" {
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			if t := strings.TrimSpace(content); t != "" {
				return extractLastLine(t)
			}
		case []any:
			var parts []string
			for _, entry := range content {
				obj, ok := entry.(map[string]any)
				if !ok {
					continue
				}
				if text, ok := obj["text"].(string); ok && strings.TrimSpace(text) != "" {
					parts = append(parts, text)
				}
			}
			if len(parts) > 0 {
				return extractLastLine(strings.Join(parts, "\n"))
			}
		}
	}
	return ""
}

// extractLastLine — openclaw이 유저 메시지 앞에 시스템 컨텍스트를 붙이므로
// 실제 유저 입력은 마지막 줄에 있음
func extractLastLine(s string) string {
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if t := strings.TrimSpace(lines[i]); t != "" {
			// "[Tue 2026-04-07 05:40 UTC] [gcp_send] text" 형태에서 timestamp 제거
			// 단, 제거 후 남은 부분도 "[..."로 시작해야 timestamp prefix임
			// (그렇지 않으면 "[gcp_send] text" 같은 태그 자체가 제거되는 버그 발생)
			if idx := strings.Index(t, "] "); idx != -1 && strings.HasPrefix(t, "[") {
				candidate := strings.TrimSpace(t[idx+2:])
				if candidate != "" && strings.HasPrefix(candidate, "[") {
					return candidate
				}
			}
			return t
		}
	}
	return strings.TrimSpace(s)
}

func (s *Server) resolveTemplateCredentials(ctx context.Context, text string) (string, error) {
	// When the org-llm-proxy is configured, credential resolution moves to
	// the cloud. Pass {{CREDENTIAL:*}} placeholders through unchanged so that
	// the cloud proxy (via boan-org-credential-gate) substitutes them right
	// before the upstream call. Plaintext never touches this host.
	if s.cfg != nil && strings.TrimSpace(s.cfg.OrgLLMProxyURL) != "" && strings.TrimSpace(s.cfg.OrgLLMProxyToken) != "" {
		return text, nil
	}

	var firstErr error
	out := credRefRe.ReplaceAllStringFunc(text, func(match string) string {
		nameMatch := credRefRe.FindStringSubmatch(match)
		if len(nameMatch) != 2 {
			return match
		}
		// Skip placeholders produced by sanitizeCredentialReadableText — they are
		// redaction markers, not references to stored credentials.
		if strings.HasPrefix(nameMatch[1], "REDACTED_") {
			return match
		}
		key, err := credential.Resolve(ctx, s.cfg.CredentialFilterURL, s.cfg.OrgID, nameMatch[1])
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return match
		}
		return key
	})
	if firstErr != nil {
		return "", firstErr
	}
	return out, nil
}

// testRegistryLLMCurl — LLM 등록 전 실제 호출 테스트.
// curl template의 {{MESSAGE}}/{{IMAGE_BASE64}}를 ping 값으로 치환하고
// {{CREDENTIAL:name}}을 실제 키로 치환한 후 한 번 호출해본다.
func (s *Server) testRegistryLLMCurl(ctx context.Context, orgID, curlTemplate string) error {
	// 64x64 빨간색 사각형 PNG (UI에서 보여주는 테스트 이미지와 동일)
	testPNG := "iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAAAaElEQVR42u3RAQ0AAAjDMK5/aiDg40iLg6ZJk5SSDKAJgAEoAAYwAAVgAAvAAQwAA1AABjAAAxiAAjCABRiAAjCABRiAAjCABRiAAjCABRiAAjCABRiAAjCABRiAAjCABRiAAjCABRiAAjCABTwLIQABBpiZ4QAAAABJRU5ErkJggg=="
	expanded := curlTemplate
	expanded = strings.ReplaceAll(expanded, "{{MESSAGE}}", "What color is this image? Answer in one word.")
	expanded = strings.ReplaceAll(expanded, "{{IMAGE_BASE64}}", testPNG)
	expanded = strings.ReplaceAll(expanded, `'"$IMG_BASE64"'`, testPNG)
	expanded = strings.ReplaceAll(expanded, "$IMG_BASE64", testPNG)

	_, endpoint, headers, body := parseCurlTemplate(expanded)
	if endpoint == "" {
		return fmt.Errorf("curl에서 endpoint 추출 불가")
	}
	if body == "" {
		return fmt.Errorf("curl에서 -d 본문 추출 불가")
	}

	// {{CREDENTIAL:name}} → 실제 키 치환 (헤더 + 본문 모두)
	for k, v := range headers {
		resolved, err := s.resolveTemplateCredentials(ctx, v)
		if err != nil {
			return fmt.Errorf("credential 치환 실패 (header %s): %w", k, err)
		}
		headers[k] = resolved
	}
	resolvedBody, err := s.resolveTemplateCredentials(ctx, body)
	if err != nil {
		return fmt.Errorf("credential 치환 실패 (body): %w", err)
	}

	log.Printf("[register-test] endpoint=%s body_len=%d", endpoint, len(resolvedBody))
	// 디버그: 실제 전송 body 일부 (이미지 데이터는 잘림)
	preview := resolvedBody
	if len(preview) > 500 {
		preview = preview[:500] + "..."
	}
	log.Printf("[register-test] body_preview=%s", preview)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(resolvedBody))
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := noProxyHTTPClient(60 * time.Second).Do(req)
	if err != nil {
		return fmt.Errorf("HTTP 호출 실패: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	log.Printf("[register-test] status=%d body=%.200s", resp.StatusCode, string(respBody))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

// evaluateGuardrailLocal — boan-proxy에서 직접 G2 가드레일 LLM을 호출.
// policy-server에서 헌법만 가져오고, G2 역할 LLM이 빠르게 (decision, reason)만 반환.
func (s *Server) evaluateGuardrailLocal(ctx context.Context, orgID, text, mode string) (decision, reason, response string, err error) {
	// 1. 헌법 가져오기
	constitution, cErr := s.guardrail.GetConstitution(ctx, orgID)
	if cErr != nil || strings.TrimSpace(constitution) == "" {
		return "block", "헌법을 가져올 수 없음 — fail-closed", "", cErr
	}

	// 2. G2 역할 LLM 조회 (작은 모델, 빠른 응답)
	entry, lErr := s.loadLLMByRole(ctx, "g2")
	if lErr != nil || entry == nil {
		return "block", "G2 LLM이 등록되지 않음 — fail-closed", "", lErr
	}

	// 3. JSON-first 프롬프트 — 첫 토큰이 "{" 가 되도록 강제.
	// reasoning 모델(gemma cloud 등)이 CoT preamble 을 뱉어 토큰 예산을 모두
	// 소진하면 JSON 이 나오지 않아 파싱 실패하므로, JSON 을 맨 앞에 배치하도록
	// 명시적으로 요구한다.
	systemPrompt := fmt.Sprintf(
		"You are a security guardrail. Respond with ONE LINE of strict JSON ONLY.\n"+
			"The very first character of your response MUST be \"{\".\n"+
			"Do not think out loud. Do not explain. Do not add markdown.\n"+
			"Schema: {\"decision\":\"allow|ask|block\",\"reason\":\"<10 words>\"}\n\n"+
			"Constitution:\n%s",
		strings.TrimSpace(constitution),
	)
	userPrompt := text

	// G2 전용 호출 — max_tokens=500 (CoT 모델도 JSON 까지 도달할 여유 확보).
	// callRegistryLLM 이 curl_template body 에 max_tokens 를 강제 주입한다.
	out, fErr := s.callRegistryLLM(ctx, entry, systemPrompt, userPrompt, 500)
	if fErr != nil {
		return "block", "G2 LLM 호출 실패: " + fErr.Error(), "", fErr
	}

	content := extractContent(out)
	if content == "" {
		return "block", "G2 LLM 빈 응답", "", nil
	}

	var parsed struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	// 첫 번째 완결된 JSON 오브젝트를 추출. LastIndex("}") 로 찾으면 모델이
	// 뒤에 붙이는 tokenizer artifact(`<|turn|`) 나 추가 텍스트/JSON 때문에
	// 전체 범위가 valid JSON 이 아니게 된다.
	if obj := extractFirstJSONObject(content); obj != "" {
		_ = json.Unmarshal([]byte(obj), &parsed)
	}
	if parsed.Decision == "" {
		log.Printf("[G2] parse-fail content=%.500q", content)
		return "block", "G2 응답 파싱 실패: " + content[:min(80, len(content))], "", nil
	}
	parsed.Decision = strings.ToLower(strings.TrimSpace(parsed.Decision))
	if parsed.Decision != "allow" && parsed.Decision != "ask" && parsed.Decision != "block" {
		return "block", "G2 잘못된 decision: " + parsed.Decision, "", nil
	}
	return parsed.Decision, parsed.Reason, "", nil
}

func extractContent(out map[string]any) string {
	if rawChoices, e := json.Marshal(out["choices"]); e == nil {
		var choices []struct {
			Message struct{ Content string `json:"content"` } `json:"message"`
		}
		if json.Unmarshal(rawChoices, &choices) == nil && len(choices) > 0 {
			return strings.TrimSpace(choices[0].Message.Content)
		}
	}
	return ""
}

func min(a, b int) int { if a < b { return a }; return b }

// callRegistryLLM — 특정 LLM entry로 직접 호출 (max_tokens 지정 가능)
//
// curl_template 이 있으면 그 body 를 그대로 사용하고 {{MESSAGE}} 를 system+user
// 프롬프트로 치환한다 (entry.Name 은 사용자 라벨일 뿐이므로 payload 의
// "model" 필드로 절대 쓰지 않는다 — 실제 모델명은 curl_template body 안에 있다).
// body 가 없을 때만 fallback 으로 entry.Name 을 model 로 사용.
func (s *Server) callRegistryLLM(ctx context.Context, entry *registryLLM, systemPrompt, userPrompt string, maxTokens int) (map[string]any, error) {
	_, endpoint, headers, body := parseCurlTemplate(entry.CurlTemplate)
	if endpoint == "" {
		endpoint = entry.Endpoint
	}
	if endpoint == "" {
		return nil, fmt.Errorf("endpoint empty for %s", entry.Name)
	}
	for k, v := range headers {
		if resolved, err := s.resolveTemplateCredentials(ctx, v); err == nil {
			headers[k] = resolved
		}
	}

	if body != "" {
		// curl_template body 존재 → {{MESSAGE}} 를 system+user 프롬프트로 치환해서 전송
		normalized, err := renderTemplateBody(body, systemPrompt+"\n\n"+userPrompt)
		if err != nil {
			return nil, err
		}
		// G2/G3 guardrail 호출은 짧은 JSON 응답만 필요하므로, 사용자 curl_template
		// 이 max_tokens 를 생략했거나 너무 작게 설정한 경우에도 maxTokens 인자를
		// 강제로 주입한다. CoT/reasoning 모델이 preamble 을 내뱉어 토큰 예산을
		// 모두 소진하고 JSON 을 못 내는 증상의 근본 원인.
		if maxTokens > 0 {
			normalized = injectMaxTokens(normalized, maxTokens)
		}
		body = normalized
	} else {
		payload := map[string]any{
			"model":  entry.Name,
			"stream": false,
			"messages": []map[string]string{
				{"role": "system", "content": systemPrompt},
				{"role": "user", "content": userPrompt},
			},
			"max_tokens":  maxTokens,
			"temperature": 0,
		}
		raw, _ := json.Marshal(payload)
		body = string(raw)
	}

	if headers == nil {
		headers = map[string]string{}
	}
	if headers["Content-Type"] == "" {
		headers["Content-Type"] = "application/json"
	}
	// G2/G3 가드레일 호출 — 구름 모델(gemma4:31b-cloud 등) 지연 감안 90초
	respRaw, status, err := s.dispatchLLMRequest(ctx, endpoint, headers, []byte(body), 90*time.Second)
	if err != nil {
		return nil, err
	}
	if status >= 300 {
		return nil, fmt.Errorf("upstream %d: %s", status, string(respRaw[:min(200, len(respRaw))]))
	}
	return translateUpstreamToOpenAI(entry.Name, respRaw)
}

func (s *Server) forwardSelectedLLM(ctx context.Context, orgID, prompt string, openAIReq map[string]any) (map[string]any, error) {
	entry, err := s.loadSelectedRegistryLLM(ctx)
	if err != nil {
		return nil, err
	}
	prompt = sanitizeCredentialReadableText(prompt)
	_, endpoint, headers, body := parseCurlTemplate(entry.CurlTemplate)
	if endpoint == "" {
		endpoint = entry.Endpoint
	}
	if endpoint == "" {
		return nil, fmt.Errorf("selected llm endpoint is empty")
	}
	if body == "" {
		payload := map[string]any{
			"model":  entry.Name,
			"stream": false,
			"messages": []map[string]any{
				{
					"role":    "system",
					"content": "When your response includes credential references, always use the exact {{CREDENTIAL:name}} placeholder syntax. Never substitute, expand, or remove credential placeholders.",
				},
				{
					"role":    "user",
					"content": prompt,
				},
			},
		}
		if maxTokens, ok := openAIReq["max_tokens"]; ok {
			payload["max_tokens"] = maxTokens
		}
		raw, _ := json.Marshal(payload)
		body = string(raw)
	} else {
		normalized, err := renderTemplateBody(body, prompt)
		if err != nil {
			return nil, err
		}
		body = normalized
	}
	for key, value := range headers {
		resolved, err := s.resolveTemplateCredentials(ctx, value)
		if err != nil {
			return nil, err
		}
		headers[key] = resolved
	}

	if headers == nil {
		headers = map[string]string{}
	}
	if headers["Content-Type"] == "" {
		headers["Content-Type"] = "application/json"
	}
	// Chat LLM (cloud 대형 모델 지원 위해 3분)
	raw, status, err := s.dispatchLLMRequest(ctx, endpoint, headers, []byte(body), 180*time.Second)
	if err != nil {
		return nil, err
	}
	if status >= 300 {
		return nil, fmt.Errorf("upstream returned %d: %s", status, strings.TrimSpace(string(raw)))
	}
	out, err := translateUpstreamToOpenAI(entry.Name, raw)
	if err != nil {
		return nil, err
	}
	return s.sanitizeOpenAIResponseForOrg(ctx, orgID, out), nil
}

// forwardActionLLM — computer-use agent 전용: system/user 메시지를 분리하여 전송
func (s *Server) forwardActionLLM(ctx context.Context, orgID, systemPrompt, userPrompt string) (map[string]any, error) {
	entry, err := s.loadSelectedRegistryLLM(ctx)
	if err != nil {
		return nil, err
	}
	_, endpoint, headers, body := parseCurlTemplate(entry.CurlTemplate)
	if endpoint == "" {
		endpoint = entry.Endpoint
	}
	if endpoint == "" {
		return nil, fmt.Errorf("selected llm endpoint is empty")
	}
	if body == "" {
		payload := map[string]any{
			"model":  entry.Name,
			"stream": false,
			"messages": []map[string]any{
				{"role": "system", "content": systemPrompt},
				{"role": "user", "content": userPrompt},
			},
			"max_tokens": 512,
		}
		raw, _ := json.Marshal(payload)
		body = string(raw)
	} else {
		// curl template가 있으면 user prompt만 렌더링
		normalized, err := renderTemplateBody(body, systemPrompt+"\n\n"+userPrompt)
		if err != nil {
			return nil, err
		}
		body = normalized
	}
	for key, value := range headers {
		resolved, err := s.resolveTemplateCredentials(ctx, value)
		if err != nil {
			return nil, err
		}
		headers[key] = resolved
	}
	if headers == nil {
		headers = map[string]string{}
	}
	if headers["Content-Type"] == "" {
		headers["Content-Type"] = "application/json"
	}
	log.Printf("[computer-use/agent] action LLM request: model=%s endpoint=%s bodyLen=%d", entry.Name, endpoint, len(body))
	// Action LLM (computer-use 전용) — cloud 모델 지연 감안 3분
	raw, status, err := s.dispatchLLMRequest(ctx, endpoint, headers, []byte(body), 180*time.Second)
	if err != nil {
		return nil, err
	}
	log.Printf("[computer-use/agent] action LLM response: status=%d bodyLen=%d body=%s", status, len(raw), func() string {
		if len(raw) > 500 { return string(raw[:500]) + "..." }
		return string(raw)
	}())
	if status >= 300 {
		return nil, fmt.Errorf("upstream returned %d: %s", status, strings.TrimSpace(string(raw)))
	}
	out, err := translateUpstreamToOpenAI(entry.Name, raw)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func noProxyHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// dispatchLLMRequest is the single egress point for every LLM upstream call.
// External hosts are tunneled through boan-org-llm-proxy so that this host
// never makes direct outbound connections to LLM providers. Local/internal
// hosts listed in OrgLLMProxyBypassHosts (e.g. boan-grounding) bypass the
// proxy and are called directly on the docker network.
//
// Returns (body, status, error). status is the upstream status code.
func (s *Server) dispatchLLMRequest(ctx context.Context, endpoint string, headers map[string]string, body []byte, timeout time.Duration) ([]byte, int, error) {
	proxyURL := strings.TrimRight(s.cfg.OrgLLMProxyURL, "/")
	proxyToken := strings.TrimSpace(s.cfg.OrgLLMProxyToken)

	parsed, err := neturl.Parse(endpoint)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid endpoint url: %w", err)
	}
	host := strings.ToLower(parsed.Hostname())

	bypass := proxyURL == "" || proxyToken == "" || hostInBypassList(host, s.cfg.OrgLLMProxyBypassHosts)

	if bypass {
		return directHTTPCall(ctx, endpoint, headers, body, timeout)
	}

	// Sign a short-lived device JWT so the Cloud Run service can verify
	// both the shared bearer token AND that this specific device is
	// allowed. Missing identity is non-fatal — server may still accept
	// bearer-only (during P3 rollout) but will refuse once the JWT gate
	// is enabled in cloud env.
	var deviceJWT string
	if s.device != nil {
		if tok, err := s.device.SignJWT(deviceJWTAudience, s.cfg.OrgID, deviceJWTTTL); err == nil {
			deviceJWT = tok
		} else {
			log.Printf("device JWT sign failed (continuing bearer-only): %v", err)
		}
	}
	return forwardViaOrgProxy(ctx, proxyURL, proxyToken, s.cfg.OrgID, deviceJWT, endpoint, headers, body, timeout)
}

func hostInBypassList(host, csv string) bool {
	if host == "" {
		return true
	}
	for _, item := range strings.Split(csv, ",") {
		item = strings.TrimSpace(strings.ToLower(item))
		if item == "" {
			continue
		}
		if host == item || strings.HasSuffix(host, "."+item) {
			return true
		}
	}
	return false
}

func directHTTPCall(ctx context.Context, endpoint string, headers map[string]string, body []byte, timeout time.Duration) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := noProxyHTTPClient(timeout).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return raw, resp.StatusCode, nil
}

type orgProxyForwardRequest struct {
	OrgID     string            `json:"org_id,omitempty"`
	CallerID  string            `json:"caller_id,omitempty"`
	Target    string            `json:"target"`
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers"`
	BodyB64   string            `json:"body_b64"`
	TimeoutMs int               `json:"timeout_ms"`
}

type orgProxyForwardResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	BodyB64 string            `json:"body_b64"`
}

func forwardViaOrgProxy(ctx context.Context, proxyURL, proxyToken, orgID, deviceJWT, endpoint string, headers map[string]string, body []byte, timeout time.Duration) ([]byte, int, error) {
	envelope := orgProxyForwardRequest{
		OrgID:     orgID,
		CallerID:  "boan-proxy",
		Target:    endpoint,
		Method:    http.MethodPost,
		Headers:   headers,
		BodyB64:   base64.StdEncoding.EncodeToString(body),
		TimeoutMs: int(timeout / time.Millisecond),
	}
	envRaw, err := json.Marshal(envelope)
	if err != nil {
		return nil, 0, err
	}

	// Client timeout must exceed upstream timeout to give the proxy time to
	// round-trip (add a 30s buffer for upstream + proxy overhead).
	clientTimeout := timeout + 30*time.Second

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, proxyURL+"/v1/forward", bytes.NewReader(envRaw))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+proxyToken)
	req.Header.Set("Content-Type", "application/json")
	if deviceJWT != "" {
		req.Header.Set("X-Boan-Device-JWT", deviceJWT)
	}

	resp, err := noProxyHTTPClient(clientTimeout).Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("org-llm-proxy call failed: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, resp.StatusCode, fmt.Errorf("org-llm-proxy returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out orgProxyForwardResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, 0, fmt.Errorf("org-llm-proxy response parse: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(out.BodyB64)
	if err != nil {
		return nil, 0, fmt.Errorf("org-llm-proxy body_b64 decode: %w", err)
	}
	return decoded, out.Status, nil
}

// extractFirstJSONObject — brace-depth 를 세어 가장 앞의 완결된 JSON
// 오브젝트 substring 을 반환한다. 문자열 리터럴 안의 `{`/`}` 는 무시한다.
// 닫히지 않으면 빈 문자열.
func extractFirstJSONObject(s string) string {
	start := strings.Index(s, "{")
	if start < 0 {
		return ""
	}
	depth := 0
	inString := false
	escape := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if inString {
			if c == '\\' {
				escape = true
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

// injectMaxTokens — G2 가드레일 호출 전용. curl_template body 가 JSON 이면
//   - max_tokens 를 n 이상으로 강제 (CoT + JSON 둘 다 들어갈 여유)
//   - Ollama chat 호출은 `"format": "json"` 을 강제해 JSON 출력 보장
//     (reasoning 모델이 "1. Analyze the Request:..." CoT 만 뱉어 JSON 파싱
//     실패하는 현상의 근본 대응. format=json 이면 Ollama 가 grammar 제약으로
//     첫 글자부터 JSON 만 나오게 함)
// JSON 이 아니면 body 그대로 반환.
func injectMaxTokens(body string, n int) string {
	var obj map[string]any
	if err := json.Unmarshal([]byte(body), &obj); err != nil {
		return body
	}
	atLeastN := func(m map[string]any, key string) {
		if v, ok := m[key]; ok {
			if f, ok := v.(float64); ok && int(f) >= n {
				return
			}
		}
		m[key] = n
	}
	// OpenAI / Anthropic / Ollama chat endpoint 은 max_tokens 를 따른다.
	atLeastN(obj, "max_tokens")
	// Ollama /api/generate 는 options.num_predict 를 따른다.
	if opts, ok := obj["options"].(map[string]any); ok {
		atLeastN(opts, "num_predict")
		obj["options"] = opts
	}
	// Gemini generateContent 는 generationConfig.maxOutputTokens.
	if cfg, ok := obj["generationConfig"].(map[string]any); ok {
		atLeastN(cfg, "maxOutputTokens")
		obj["generationConfig"] = cfg
	}
	// Ollama chat endpoint 특성 — messages 배열 + options 객체가 있으면 Ollama 로 간주.
	// `format: "json"` 을 설정하면 출력이 valid JSON 한 개로 고정된다.
	// `think: false` 도 유지/강제 — CoT 가 JSON 앞에 붙는 것을 막음.
	if _, hasMessages := obj["messages"]; hasMessages {
		if _, hasOptions := obj["options"]; hasOptions {
			if _, already := obj["format"]; !already {
				obj["format"] = "json"
			}
			obj["think"] = false
		}
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return string(raw)
}

func renderTemplateBody(body, prompt string) (string, error) {
	var payload any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		return "", fmt.Errorf("invalid template body: %w", err)
	}
	payload = replaceTemplateValue(payload, prompt)
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func replaceTemplateValue(value any, prompt string) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, inner := range typed {
			out[key] = replaceTemplateValue(inner, prompt)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, inner := range typed {
			out[i] = replaceTemplateValue(inner, prompt)
		}
		return out
	case string:
		return strings.ReplaceAll(typed, "{{MESSAGE}}", prompt)
	default:
		return value
	}
}

func translateUpstreamToOpenAI(model string, raw []byte) (map[string]any, error) {
	var openAI map[string]any
	if err := json.Unmarshal(raw, &openAI); err == nil {
		if _, ok := openAI["choices"]; ok {
			return openAI, nil
		}
	}
	var ollama struct {
		Model      string `json:"model"`
		CreatedAt  string `json:"created_at"`
		Done       bool   `json:"done"`
		DoneReason string `json:"done_reason"`
		Message    struct {
			Role     string `json:"role"`
			Content  string `json:"content"`
			Thinking string `json:"thinking"`
		} `json:"message"`
		PromptEvalCount int `json:"prompt_eval_count"`
		EvalCount       int `json:"eval_count"`
	}
	if err := json.Unmarshal(raw, &ollama); err == nil {
		content := strings.TrimSpace(ollama.Message.Content)
		if content == "" {
			content = strings.TrimSpace(ollama.Message.Thinking)
		}
		finishReason := strings.TrimSpace(ollama.DoneReason)
		if finishReason == "" {
			finishReason = "stop"
		}
		return map[string]any{
			"id":      fmt.Sprintf("ollama-%d", time.Now().UnixNano()),
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   firstNonEmpty(ollama.Model, model),
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    firstNonEmpty(ollama.Message.Role, "assistant"),
						"content": content,
					},
					"finish_reason": finishReason,
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     ollama.PromptEvalCount,
				"completion_tokens": ollama.EvalCount,
				"total_tokens":      ollama.PromptEvalCount + ollama.EvalCount,
			},
		}, nil
	}
	// Try NDJSON (Ollama streaming format: multiple JSON objects, one per line)
	{
		lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
		if len(lines) > 1 {
			var accumulated strings.Builder
			var ndjsonModel string
			for _, line := range lines {
				line = bytes.TrimSpace(line)
				if len(line) == 0 {
					continue
				}
				var chunk struct {
					Model   string `json:"model"`
					Done    bool   `json:"done"`
					Message struct {
						Content  string `json:"content"`
						Thinking string `json:"thinking"`
					} `json:"message"`
				}
				if err := json.Unmarshal(line, &chunk); err == nil {
					if chunk.Model != "" {
						ndjsonModel = chunk.Model
					}
					if !chunk.Done {
						accumulated.WriteString(chunk.Message.Content)
					}
				}
			}
			if accumulated.Len() > 0 {
				return map[string]any{
					"id":      fmt.Sprintf("ollama-%d", time.Now().UnixNano()),
					"object":  "chat.completion",
					"created": time.Now().Unix(),
					"model":   firstNonEmpty(ndjsonModel, model),
					"choices": []map[string]any{
						{
							"index": 0,
							"message": map[string]any{
								"role":    "assistant",
								"content": accumulated.String(),
							},
							"finish_reason": "stop",
						},
					},
				}, nil
			}
		}
	}

	var anthropic struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Usage map[string]any `json:"usage"`
	}
	if err := json.Unmarshal(raw, &anthropic); err == nil && len(anthropic.Content) > 0 {
		parts := make([]string, 0, len(anthropic.Content))
		for _, c := range anthropic.Content {
			if strings.TrimSpace(c.Text) != "" {
				parts = append(parts, c.Text)
			}
		}
		return map[string]any{
			"id":      anthropic.ID,
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   firstNonEmpty(anthropic.Model, model),
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": strings.Join(parts, "\n"),
					},
					"finish_reason": "stop",
				},
			},
			"usage": anthropic.Usage,
		}, nil
	}
	return map[string]any{
		"id":      fmt.Sprintf("boan-%d", time.Now().UnixNano()),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]any{
					"role":    "assistant",
					"content": "(모델 응답을 파싱할 수 없습니다)",
				},
				"finish_reason": "stop",
			},
		},
	}, nil
}

func (s *Server) sanitizeOpenAIResponseForOrg(ctx context.Context, orgID string, resp map[string]any) map[string]any {
	known := s.credentialPlaceholderMap(ctx, orgID)
	passthrough := s.credentialPassthroughValues(orgID)
	choicesRaw, ok := resp["choices"].([]any)
	if ok {
		for _, choiceRaw := range choicesRaw {
			choice, ok := choiceRaw.(map[string]any)
			if !ok {
				continue
			}
			message, ok := choice["message"].(map[string]any)
			if !ok {
				continue
			}
			if content, ok := message["content"].(string); ok {
				message["content"] = sanitizeCredentialReadableTextWithKnown(content, known, passthrough)
			}
		}
		return resp
	}
	choicesMap, ok := resp["choices"].([]map[string]any)
	if ok {
		for _, choice := range choicesMap {
			message, ok := choice["message"].(map[string]any)
			if !ok {
				continue
			}
			if content, ok := message["content"].(string); ok {
				message["content"] = sanitizeCredentialReadableTextWithKnown(content, known, passthrough)
			}
		}
	}
	return resp
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
