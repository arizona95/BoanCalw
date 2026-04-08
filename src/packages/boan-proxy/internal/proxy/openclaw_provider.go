package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/credential"
)

type registryLLM struct {
	Name              string `json:"name"`
	Endpoint          string `json:"endpoint"`
	Type              string `json:"type"`
	CurlTemplate      string `json:"curl_template"`
	ImageCurlTemplate string `json:"image_curl_template"`
	IsSecurityLLM     bool   `json:"is_security_llm"`
	IsSecurityLMM     bool   `json:"is_security_lmm"`
	Healthy           bool   `json:"healthy"`
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

func (s *Server) loadSelectedRegistryLLM(ctx context.Context) (*registryLLM, error) {
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
		return nil, fmt.Errorf("no llm registered")
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

// loadSecurityLMM — IsSecurityLMM 로 등록된 vision 모델 반환
func (s *Server) loadSecurityLMM(ctx context.Context) (*registryLLM, error) {
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
	for _, e := range entries {
		if e.IsSecurityLMM {
			entry := e
			return &entry, nil
		}
	}
	// fallback: image 타입 중 healthy 한 것
	for _, e := range entries {
		if e.Type == "image" && e.Healthy {
			entry := e
			return &entry, nil
		}
	}
	return nil, fmt.Errorf("no security LMM registered")
}

// forwardVisionLLM — open-computer-use vision_model.call() 에 해당
// 스크린샷 base64 + 텍스트 프롬프트를 vision LMM 에 전달 → 화면 묘사/next step 텍스트 반환
func (s *Server) forwardVisionLLM(ctx context.Context, entry *registryLLM, screenshotB64, prompt string) (string, error) {
	// endpoint + headers 만 template 에서 추출 — body 는 아래에서 직접 구성
	// (image_curl_template 에 shell 변수 트릭 '"$IMG_BASE64"' 가 있어 body 파싱 불가)
	curlTmpl := entry.ImageCurlTemplate
	if curlTmpl == "" {
		curlTmpl = entry.CurlTemplate
	}
	_, endpoint, headers, tmplBody := parseCurlTemplate(curlTmpl)
	if endpoint == "" {
		endpoint = entry.Endpoint
	}
	if endpoint == "" {
		return "", fmt.Errorf("vision llm endpoint is empty")
	}

	// curl template body에서 실제 model명 추출 (entry.Name과 다를 수 있음)
	modelName := entry.Name
	if m := curlModelRe.FindStringSubmatch(tmplBody); len(m) == 2 {
		modelName = m[1]
	}

	// credential placeholder 헤더 값 해석
	for k, v := range headers {
		resolved, err := s.resolveTemplateCredentials(ctx, v)
		if err != nil {
			return "", err
		}
		headers[k] = resolved
	}

	// endpoint 패턴으로 포맷 결정:
	// /api/chat  → Ollama 포맷 (images 배열)
	// 그 외      → OpenAI vision 포맷
	var payload map[string]any
	if strings.Contains(endpoint, "/api/chat") {
		// Ollama multimodal 포맷
		payload = map[string]any{
			"model": modelName,
			"messages": []map[string]any{
				{
					"role":    "user",
					"content": prompt,
					"images":  []string{screenshotB64},
				},
			},
			"stream": false,
		}
	} else {
		// OpenAI vision 포맷
		payload = map[string]any{
			"model": modelName,
			"messages": []map[string]any{
				{
					"role": "user",
					"content": []map[string]any{
						{
							"type": "image_url",
							"image_url": map[string]string{
								"url": "data:image/png;base64," + screenshotB64,
							},
						},
						{"type": "text", "text": prompt},
					},
				},
			},
			"max_tokens": 512,
		}
	}

	raw, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := noProxyHTTPClient(60 * time.Second).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respRaw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("vision llm returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respRaw)))
	}
	out, err := translateUpstreamToOpenAI(entry.Name, respRaw)
	if err != nil {
		return "", err
	}
	// 텍스트 추출
	if rawChoices, err := json.Marshal(out["choices"]); err == nil {
		var choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal(rawChoices, &choices) == nil && len(choices) > 0 {
			return choices[0].Message.Content, nil
		}
	}
	return "", fmt.Errorf("vision llm response parse failed: %s", string(respRaw))
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(body))
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := noProxyHTTPClient(90 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewBufferString(body))
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	log.Printf("[computer-use/agent] action LLM request: model=%s endpoint=%s bodyLen=%d", entry.Name, endpoint, len(body))
	resp, err := noProxyHTTPClient(90 * time.Second).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	log.Printf("[computer-use/agent] action LLM response: status=%d bodyLen=%d body=%s", resp.StatusCode, len(raw), func() string {
		if len(raw) > 500 { return string(raw[:500]) + "..." }
		return string(raw)
	}())
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
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
