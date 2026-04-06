package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	_, endpoint, headers, _ := parseCurlTemplate(curlTmpl)
	if endpoint == "" {
		endpoint = entry.Endpoint
	}
	if endpoint == "" {
		return "", fmt.Errorf("vision llm endpoint is empty")
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
			"model": entry.Name,
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
			"model": entry.Name,
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
	parts := make([]string, 0, len(list))
	for _, item := range list {
		msg, ok := item.(map[string]any)
		if !ok {
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			if strings.TrimSpace(content) != "" {
				parts = append(parts, content)
			}
		case []any:
			for _, entry := range content {
				obj, ok := entry.(map[string]any)
				if !ok {
					continue
				}
				if text, ok := obj["text"].(string); ok && strings.TrimSpace(text) != "" {
					parts = append(parts, text)
				}
			}
		}
	}
	return strings.Join(parts, "\n")
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
			"model": entry.Name,
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
		if content == "" {
			content = strings.TrimSpace(string(raw))
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
					"content": string(raw),
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
