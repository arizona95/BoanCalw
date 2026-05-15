package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/guardrail"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/imagehash"
)

// decodeRuneStdlib — utf8.DecodeRune 래퍼. decodeRune 가 image_gate.go 안에
// inline 처럼 보이게 하기 위한 indirection.
func decodeRuneStdlib(b []byte) (rune, int) {
	return utf8.DecodeRune(b)
}

// ImageGateResult — one image's evaluation outcome. Action is "allow",
// "block" (G1_img pHash match), or "ask" (G2_img vision-LLM match → HITL).
// When blocked, Replacement is the text that should swap in for the image
// content part. Tier reflects which gate produced the decision.
type ImageGateResult struct {
	Action      string // allow | block | ask
	Tier        string // GI1 | GI2 | "" (allow)
	MatchedHash string
	Distance    int
	Replacement string
	Reason      string
	Bytes       []byte // image bytes preserved for downstream HITL (GI2 ask path)
}

// EvaluateImageContent walks an OpenAI-shaped messages array and runs each
// embedded image part through GI1 + (optionally) GI2. Returns one result per
// image, in encounter order. Access-level gating:
//   - "allow": GI1 only (deterministic pHash; no vision-LLM call).
//   - "ask"  : GI1 → GI2 (vision-LLM via cloud llm-proxy).
//   - "deny" : caller blocks upstream; we still run GI1 for completeness.
//
// Recognised shapes:
//   - {"type": "image_url", "image_url": {"url": "data:image/png;base64,..."}}
//   - {"type": "image", "source": {"data": "<base64>"}} (Anthropic style)
func (s *Server) EvaluateImageContent(ctx context.Context, orgID, accessLevel string, messages any) []ImageGateResult {
	store, descs, err := s.guardrail.GI1Store(ctx, orgID)
	if err != nil {
		return nil
	}
	if (store == nil || store.Len() == 0) && len(descs) == 0 {
		return nil
	}
	var results []ImageGateResult
	walkImages(messages, func(b64 string) {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return
		}
		res := s.evaluateImageDecoded(ctx, orgID, accessLevel, raw, store, descs)
		if res.Action == "" || res.Action == "allow" {
			return
		}
		results = append(results, res)
	})
	return results
}

// EvaluateImageBytes runs the full GI1 (+ GI2 if accessLevel == "ask") chain
// on a single image already in memory (file-transfer path).
func (s *Server) EvaluateImageBytes(ctx context.Context, orgID, accessLevel string, data []byte) ImageGateResult {
	store, descs, err := s.guardrail.GI1Store(ctx, orgID)
	if err != nil {
		return ImageGateResult{}
	}
	if (store == nil || store.Len() == 0) && len(descs) == 0 {
		return ImageGateResult{}
	}
	return s.evaluateImageDecoded(ctx, orgID, accessLevel, data, store, descs)
}

// evaluateImageDecoded — GI1 항상 (deterministic, cheap), GI2 는 accessLevel
// == "ask" 일 때만. allow 사용자는 vision-LLM 비용 자체를 안 치고, deny 는
// 위 layer 에서 block 되므로 여기서는 GI1 만 평가.
func (s *Server) evaluateImageDecoded(
	ctx context.Context,
	orgID, accessLevel string,
	raw []byte,
	store *imagehash.Store,
	descs []guardrail.GI2Description,
) ImageGateResult {
	if store != nil && store.Len() > 0 {
		hash, err := imagehash.Compute(bytes.NewReader(raw))
		if err == nil {
			if entry, dist := store.MatchHex(hash); dist >= 0 {
				repl := entry.Replacement
				if strings.TrimSpace(repl) == "" {
					repl = fmt.Sprintf("[guardrail::G1_img::block hash=%s d=%d]", entry.Hash16, dist)
				}
				return ImageGateResult{
					Action: "block", Tier: "G1_img",
					MatchedHash: entry.Hash16, Distance: dist,
					Replacement: repl,
					Reason:      fmt.Sprintf("G1_img pHash match (%s)", entry.Description),
				}
			}
		}
	}
	// allow 사용자는 GI1 만 — vision LLM 비용 안 침. ask 일 때만 GI2 진입.
	if strings.ToLower(strings.TrimSpace(accessLevel)) != "ask" {
		return ImageGateResult{Action: "allow"}
	}
	if len(descs) == 0 {
		return ImageGateResult{Action: "allow"}
	}
	matched, action, err := s.gi2VisionMatch(ctx, orgID, raw, descs)
	if err != nil || matched == "" {
		return ImageGateResult{Action: "allow"}
	}
	repl := fmt.Sprintf("[guardrail::GI2::%s desc=%q]", action, matched)
	return ImageGateResult{
		Action: action, Tier: "G2_img",
		Replacement: repl,
		Reason:      fmt.Sprintf("G2_img vision-LLM match: %q", matched),
		Bytes:       raw,
	}
}


// isImageFilename — true if the trailing extension is one of the formats
// our pHash library decodes. Kept narrow on purpose: bmp/webp/tiff are not
// included because the imagehash package doesn't register a decoder for them.
func isImageFilename(name string) bool {
	low := strings.ToLower(name)
	for _, ext := range []string{".png", ".jpg", ".jpeg", ".gif"} {
		if strings.HasSuffix(low, ext) {
			return true
		}
	}
	return false
}

// FileKind — 파일 전송 분류. 정책상 text/image 만 통과 가능, 그 외는 drop.
type FileKind string

const (
	FileKindText  FileKind = "text"
	FileKindImage FileKind = "image"
	FileKindDrop  FileKind = "drop" // 암호화 / 압축 / 알 수 없는 바이너리
)

// ClassifyFile — 파일 내용 + 이름으로 text/image/drop 분류.
//   - image: 이미지 확장자 + Go image.Decode 가능
//   - text : UTF-8 valid + 출력 가능한 문자 비율 ≥ 95%
//   - drop : 그 외 (암호화·압축·바이너리)
//
// magic-byte sniffing (image) → UTF-8 validity → printable-ratio fallback.
func ClassifyFile(name string, content []byte) FileKind {
	if isImageFilename(name) {
		if _, err := imagehash.Compute(bytes.NewReader(content)); err == nil {
			return FileKindImage
		}
		// 확장자는 이미지인데 decode 실패 → 손상 / 위장. drop.
		return FileKindDrop
	}
	if len(content) == 0 {
		return FileKindText // empty 파일 = 텍스트 취급 (가드레일이 통과시킬 것)
	}
	if !utf8Valid(content) {
		return FileKindDrop
	}
	if printableRatio(content) < 0.95 {
		return FileKindDrop
	}
	return FileKindText
}

func utf8Valid(b []byte) bool {
	for i := 0; i < len(b); {
		r, size := decodeRune(b[i:])
		if r == 0xFFFD && size == 1 {
			return false
		}
		i += size
	}
	return true
}

// decodeRune wraps utf8.DecodeRune via standard lib but kept inline-private
// so we don't pull "unicode/utf8" into the package's import list at top of file.
func decodeRune(b []byte) (rune, int) {
	return decodeRuneStdlib(b)
}

// printableRatio — UTF-8 으로 디코딩된 rune 중 출력 가능 비율.
// 출력 가능 = 가시 문자 + 일반 공백 (space, tab, newline, CR). NUL / 제어 문자
// 비중이 높으면 binary 로 간주.
func printableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 1.0
	}
	total := 0
	printable := 0
	for i := 0; i < len(b); {
		r, size := decodeRune(b[i:])
		total++
		if r == '\t' || r == '\n' || r == '\r' || (r >= 0x20 && r != 0x7f) {
			printable++
		}
		i += size
	}
	if total == 0 {
		return 1.0
	}
	return float64(printable) / float64(total)
}

// callVisionLLM — LLM Registry 의 vision-role 모델 호출. image_curl_template
// 의 {{MESSAGE}}/{{IMAGE_BASE64}}/{{CREDENTIAL:*}} 를 치환한 뒤
// dispatchLLMRequest 로 보낸다 — Ollama (`/api/chat`) 와 OpenAI
// (`/v1/chat/completions`) 둘 다 template body 가 정답이므로 우리는 그저 변수만
// 채워 넣는다. response 의 어떤 shape 인지에 맞춰 텍스트만 뽑아 반환.
func (s *Server) callVisionLLM(ctx context.Context, orgID, prompt string, imageBytes []byte) (string, error) {
	entry, err := s.loadLLMByRole(ctx, "vision")
	if err != nil || entry == nil {
		return "", fmt.Errorf("no vision LLM registered: %w", err)
	}
	tmpl := strings.TrimSpace(entry.ImageCurlTemplate)
	if tmpl == "" {
		tmpl = strings.TrimSpace(entry.CurlTemplate)
	}
	if tmpl == "" {
		return "", fmt.Errorf("vision LLM %q has no curl_template/image_curl_template", entry.Name)
	}
	b64 := base64.StdEncoding.EncodeToString(imageBytes)
	expanded := tmpl
	// Caller 가 줄바꿈 / 따옴표를 포함한 prompt 를 그대로 던질 수 있으므로 JSON-string-escape.
	promptEsc := jsonStringEscape(prompt)
	expanded = strings.ReplaceAll(expanded, "{{MESSAGE}}", promptEsc)
	expanded = strings.ReplaceAll(expanded, "{{IMAGE_BASE64}}", b64)
	// Shell-style placeholders that some registry seeds use.
	expanded = strings.ReplaceAll(expanded, `'"$IMG_BASE64"'`, b64)
	expanded = strings.ReplaceAll(expanded, "$IMG_BASE64", b64)

	_, endpoint, headers, body := parseCurlTemplate(expanded)
	if endpoint == "" || body == "" {
		return "", fmt.Errorf("parse curl_template: endpoint=%q body_len=%d", endpoint, len(body))
	}
	for k, v := range headers {
		resolved, rerr := s.resolveTemplateCredentials(ctx, v)
		if rerr != nil {
			return "", fmt.Errorf("credential resolve (header %s): %w", k, rerr)
		}
		headers[k] = resolved
	}
	resolvedBody, rerr := s.resolveTemplateCredentials(ctx, body)
	if rerr != nil {
		return "", fmt.Errorf("credential resolve (body): %w", rerr)
	}
	if _, ok := headers["Content-Type"]; !ok {
		headers["Content-Type"] = "application/json"
	}
	respBody, status, dErr := s.dispatchLLMRequest(ctx, endpoint, headers, []byte(resolvedBody), 60*time.Second)
	if dErr != nil {
		return "", fmt.Errorf("dispatch vision LLM: %w", dErr)
	}
	if status >= 400 {
		preview := string(respBody)
		if len(preview) > 200 {
			preview = preview[:200]
		}
		return "", fmt.Errorf("vision LLM returned %d: %s", status, strings.TrimSpace(preview))
	}
	return extractVisionText(respBody), nil
}

// jsonStringEscape returns s safe to embed inside a JSON string literal.
// We don't include the surrounding quotes — the template already has them.
func jsonStringEscape(s string) string {
	raw, _ := json.Marshal(s)
	if len(raw) >= 2 {
		return string(raw[1 : len(raw)-1])
	}
	return s
}

// extractVisionText tries every shape we have seen in the wild:
//   - Ollama /api/chat   → {"message": {"content": "..."}}
//   - OpenAI /v1/chat/completions → {"choices":[{"message":{"content":"..."}}]}
//   - Anthropic-style    → content as array of {type:"text", text:"..."}
//
// We bail out on the first one that yields a non-empty string.
func extractVisionText(raw []byte) string {
	var ollama struct {
		Message struct {
			Content any `json:"content"`
		} `json:"message"`
	}
	if err := json.Unmarshal(raw, &ollama); err == nil {
		if t := contentAsText(ollama.Message.Content); t != "" {
			return t
		}
	}
	var openai struct {
		Choices []struct {
			Message struct {
				Content any `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &openai); err == nil && len(openai.Choices) > 0 {
		if t := contentAsText(openai.Choices[0].Message.Content); t != "" {
			return t
		}
	}
	log.Printf("[GI2] could not extract vision text from response: %.200s", string(raw))
	return ""
}

func contentAsText(c any) string {
	switch v := c.(type) {
	case string:
		return v
	case []any:
		var sb strings.Builder
		for _, part := range v {
			if pm, ok := part.(map[string]any); ok {
				if t, ok := pm["text"].(string); ok {
					sb.WriteString(t)
				}
			}
		}
		return sb.String()
	}
	return ""
}

// gi2VisionMatch — vision-LLM 에 이미지 + admin 이 등록한 자연어 설명 리스트를
// 같이 보내서 매칭되면 매칭된 설명 + 그 설명의 action(ask/block) 을 반환.
// LLM Registry 에서 role="vision" 으로 바인딩된 모델을 사용. 미등록 / 호출
// 실패 시 ("", "", err) → caller 는 allow 로 fail-open (vision LLM 자체가
// 옵셔널한 가드레일이라 정책 누락이 차단으로 이어지면 안 됨).
func (s *Server) gi2VisionMatch(
	ctx context.Context,
	orgID string,
	imageBytes []byte,
	descs []guardrail.GI2Description,
) (matched, action string, err error) {
	if len(descs) == 0 {
		return "", "", nil
	}
	// matched description 을 골라달라는 single-shot prompt. 응답은 "MATCH: <desc>"
	// 또는 "NONE". LLM 이 형식을 안 맞춰도 substring 매칭으로 회복.
	var sb strings.Builder
	sb.WriteString("You are an image classifier for a security guardrail. ")
	sb.WriteString("Decide whether the attached image matches any of these descriptions:\n")
	for i, d := range descs {
		text := strings.TrimSpace(d.Description)
		if text == "" {
			continue
		}
		fmt.Fprintf(&sb, "%d. %s\n", i+1, text)
	}
	sb.WriteString("\nReply with exactly one line:\n")
	sb.WriteString("MATCH: <verbatim description text> — if any description fits the image.\n")
	sb.WriteString("NONE — if no description fits.\n")

	reply, err := s.callVisionLLM(ctx, orgID, sb.String(), imageBytes)
	if err != nil {
		return "", "", err
	}
	reply = strings.TrimSpace(reply)
	if strings.HasPrefix(strings.ToUpper(reply), "NONE") {
		return "", "", nil
	}
	for _, d := range descs {
		text := strings.TrimSpace(d.Description)
		if text == "" {
			continue
		}
		if strings.Contains(strings.ToLower(reply), strings.ToLower(text)) {
			a := strings.ToLower(strings.TrimSpace(d.Action))
			if a != "block" {
				a = "ask"
			}
			return text, a, nil
		}
	}
	return "", "", nil
}

// walkImages descends into the OpenAI / Anthropic chat shapes and emits the
// base64 payload for each embedded image. Strings are decoded permissively
// (we strip the `data:...;base64,` prefix if present).
func walkImages(node any, emit func(b64 string)) {
	switch v := node.(type) {
	case []any:
		for _, item := range v {
			walkImages(item, emit)
		}
	case map[string]any:
		// OpenAI-style: {"type":"image_url","image_url":{"url":"data:..."}}
		if u, ok := v["image_url"].(map[string]any); ok {
			if s, ok := u["url"].(string); ok {
				if b64 := extractBase64(s); b64 != "" {
					emit(b64)
				}
			}
		}
		// Anthropic-style: {"type":"image","source":{"type":"base64","data":"..."}}
		if src, ok := v["source"].(map[string]any); ok {
			if data, ok := src["data"].(string); ok && data != "" {
				emit(extractBase64(data))
			}
		}
		// Recurse into the rest so multi-message arrays still get visited.
		for k, val := range v {
			if k == "image_url" || k == "source" {
				continue
			}
			walkImages(val, emit)
		}
	}
}

func extractBase64(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "data:") {
		if idx := strings.Index(s, ";base64,"); idx >= 0 {
			return s[idx+len(";base64,"):]
		}
		// data: without base64 marker — treat as opaque, skip.
		return ""
	}
	// Assume already-bare base64.
	return s
}

// ApplyImageReplacements mutates an OpenAI/Anthropic messages payload in
// place so each blocked image part becomes a text part. The number of
// `block` results is consumed in walk order; extras are dropped. Returns
// the count of substitutions actually made.
func ApplyImageReplacements(messages any, results []ImageGateResult) int {
	if len(results) == 0 {
		return 0
	}
	idx := 0
	substituted := 0
	replaceImageInPlace(messages, func() (string, bool) {
		for idx < len(results) {
			cur := results[idx]
			idx++
			if cur.Action == "block" {
				substituted++
				return cur.Replacement, true
			}
		}
		return "", false
	})
	return substituted
}

func replaceImageInPlace(node any, next func() (string, bool)) {
	arr, ok := node.([]any)
	if !ok {
		// not an array — descend into maps to find arrays of content parts.
		if m, ok := node.(map[string]any); ok {
			for _, v := range m {
				replaceImageInPlace(v, next)
			}
		}
		return
	}
	for i, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		isImage := false
		if t, _ := m["type"].(string); t == "image_url" || t == "image" {
			isImage = true
		}
		if _, ok := m["image_url"].(map[string]any); ok && !isImage {
			isImage = true
		}
		if isImage {
			repl, ok := next()
			if !ok {
				continue
			}
			arr[i] = map[string]any{"type": "text", "text": repl}
			continue
		}
		// recurse — multi-message arrays / nested content.
		replaceImageInPlace(item, next)
	}
}

