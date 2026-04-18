package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg"
	"image/png"
	"io"
	"log"
	"net"
	"net/http"
	neturl "net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/credential"
)

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

// loadSecurityLMM — vision 역할에 바인딩된 LMM 반환.
// role="vision" 기준. 레거시 IsSecurityLMM 필드는 registryLLM.hasRole 에서 호환 처리됨.
func (s *Server) loadSecurityLMM(ctx context.Context) (*registryLLM, error) {
	entry, err := s.loadLLMByRole(ctx, "vision")
	if err != nil {
		return nil, fmt.Errorf("vision LMM 바인딩이 없습니다 (LLM Registry 탭에서 vision 역할을 바인딩하세요): %w", err)
	}
	return entry, nil
}

// loadGroundingLMM — grounding 역할에 바인딩된 LMM 반환.
// computer-use agent 의 click 좌표를 자연어 → 픽셀로 변환하는 데 사용.
// 바인딩 안 되어 있으면 nil 반환 (에러 아님). 호출측이 fallback 결정.
func (s *Server) loadGroundingLMM(ctx context.Context) *registryLLM {
	entry, err := s.loadLLMByRole(ctx, "grounding")
	if err != nil {
		return nil
	}
	return entry
}

// forwardGroundingLLM — vision endpoint 에 grounding 쿼리를 보내고 (x, y) 좌표 추출.
//
// description 예시: "the X close button on the Notepad title bar"
//
// 2-pass crop-and-zoom 전략:
//
//	Pass 1: 전체 화면 → 대략 위치 (rough). UGround 가 작은 element 는 ~100px 빗나감.
//	Pass 2: rough 주변 cropW x cropH 영역만 잘라서 같은 description 으로 재호출.
//	         crop 안에서 target 이 차지하는 픽셀 비율이 훨씬 커서 정확도 ↑.
//	         crop 좌표를 full image 좌표로 매핑해서 반환.
//
// crop pass 가 실패하거나 image 디코딩이 실패하면 1차 결과를 그대로 사용 (graceful fallback).
//
// UGround / OS-Atlas / Qwen-VL 류 grounding 모델은 대부분 [0, 1000) 정규화 좌표
// 를 출력. parser 와 rescaler 가 양쪽 다 처리.
//
// 지원 포맷 (모델 swap 가능):
//   - 일반 텍스트 "(x, y)"            ← UGround 기본 출력
//   - JSON {"x":N,"y":N}              (단순 모델)
//   - JSON {"point":[N,N]}            (Molmo 류)
//   - JSON {"bbox":[x1,y1,x2,y2]}     (Florence-2 류, midpoint 추출)
//   - <|box_start|>(x1,y1),(x2,y2)<|box_end|>  (OS-Atlas 토큰)
//   - <point>x,y</point>              (Qwen2-VL native)
//   - <click>x,y</click>              (MAI-UI 류)
//   - <box>x1,y1,x2,y2</box>          (Qwen-VL native)
func (s *Server) forwardGroundingLLM(ctx context.Context, entry *registryLLM, screenshotB64, description string, scrW, scrH int) (int, int, error) {
	if entry == nil {
		return 0, 0, fmt.Errorf("grounding LMM not bound")
	}
	prompt := buildGroundingPrompt(description)
	log.Printf("[grounding] pass1 model=%s desc=%q screen=%dx%d", entry.Name, description, scrW, scrH)
	raw, err := s.forwardVisionLLM(ctx, entry, screenshotB64, prompt)
	if err != nil {
		return 0, 0, fmt.Errorf("grounding llm call failed (pass1): %w", err)
	}
	log.Printf("[grounding] pass1 raw: %s", truncateForLog(raw, 200))
	roughX, roughY, ok := parseGroundingCoordinates(raw, scrW, scrH)
	if !ok {
		return 0, 0, fmt.Errorf("could not parse coordinates from pass1 response: %s", truncateForLog(raw, 200))
	}
	if roughX < 0 || roughY < 0 {
		// 모델이 명시적으로 "not found"
		return roughX, roughY, nil
	}
	log.Printf("[grounding] pass1 parsed → (%d, %d)", roughX, roughY)

	// ── Pass 2: crop-and-zoom ──────────────────────────────────────────
	// crop 크기는 화면의 1/3 ~ 1/2 정도. 목표 element 가 cropping 으로 잘리지 않게 충분히 큼.
	const cropW = 600
	const cropH = 400
	cropOffsetX, cropOffsetY, croppedB64, err := cropAroundCenter(screenshotB64, roughX, roughY, cropW, cropH)
	if err != nil {
		log.Printf("[grounding] pass2 crop failed (%v) — falling back to pass1 result", err)
		fx, fy := clampXY(roughX, roughY, scrW, scrH)
		return fx, fy, nil
	}
	cropImgW := cropW
	cropImgH := cropH
	if w, h := getImageDimensionsFromBase64(croppedB64); w > 0 && h > 0 {
		cropImgW = w
		cropImgH = h
	}
	log.Printf("[grounding] pass2 cropping center=(%d,%d) → crop offset=(%d,%d) size=%dx%d", roughX, roughY, cropOffsetX, cropOffsetY, cropImgW, cropImgH)

	raw2, err := s.forwardVisionLLM(ctx, entry, croppedB64, prompt)
	if err != nil {
		log.Printf("[grounding] pass2 llm error (%v) — using pass1 result", err)
		fx, fy := clampXY(roughX, roughY, scrW, scrH)
		return fx, fy, nil
	}
	log.Printf("[grounding] pass2 raw: %s", truncateForLog(raw2, 200))
	cropX, cropY, ok := parseGroundingCoordinates(raw2, cropImgW, cropImgH)
	if !ok {
		log.Printf("[grounding] pass2 parse failed — using pass1 result")
		fx, fy := clampXY(roughX, roughY, scrW, scrH)
		return fx, fy, nil
	}
	if cropX < 0 || cropY < 0 {
		log.Printf("[grounding] pass2 not-found → using pass1 result")
		fx, fy := clampXY(roughX, roughY, scrW, scrH)
		return fx, fy, nil
	}
	finalX := cropOffsetX + cropX
	finalY := cropOffsetY + cropY
	log.Printf("[grounding] pass2 → crop(%d,%d) → final(%d,%d)", cropX, cropY, finalX, finalY)
	fx, fy := clampXY(finalX, finalY, scrW, scrH)
	return fx, fy, nil
}

// clampXY — (x, y) 를 [0, scrW-1] x [0, scrH-1] 로 제한.
func clampXY(x, y, scrW, scrH int) (int, int) {
	if x < 0 {
		x = 0
	}
	if scrW > 0 && x >= scrW {
		x = scrW - 1
	}
	if y < 0 {
		y = 0
	}
	if scrH > 0 && y >= scrH {
		y = scrH - 1
	}
	return x, y
}

// cropAroundCenter — base64 인코딩된 이미지를 (cx, cy) 중심 cropW x cropH 영역으로 잘라서
// (offsetX, offsetY, croppedBase64, error) 를 반환. 가장자리에서 자동으로 clamp.
//
// 입력 형식은 PNG 또는 JPEG 자동 감지.
// 출력은 항상 PNG base64.
func cropAroundCenter(b64 string, cx, cy, cropW, cropH int) (int, int, string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return 0, 0, "", fmt.Errorf("base64 decode: %w", err)
	}
	src, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return 0, 0, "", fmt.Errorf("image decode: %w", err)
	}
	bounds := src.Bounds()
	srcW := bounds.Dx()
	srcH := bounds.Dy()

	// crop 영역 계산 (가장자리에서 clamp)
	x1 := cx - cropW/2
	y1 := cy - cropH/2
	if x1 < 0 {
		x1 = 0
	}
	if y1 < 0 {
		y1 = 0
	}
	x2 := x1 + cropW
	y2 := y1 + cropH
	if x2 > srcW {
		x2 = srcW
		x1 = x2 - cropW
		if x1 < 0 {
			x1 = 0
		}
	}
	if y2 > srcH {
		y2 = srcH
		y1 = y2 - cropH
		if y1 < 0 {
			y1 = 0
		}
	}

	// SubImage 로 crop (대부분의 image.Image 구현이 SubImage interface 지원)
	type subImager interface {
		SubImage(r image.Rectangle) image.Image
	}
	si, ok := src.(subImager)
	if !ok {
		return 0, 0, "", fmt.Errorf("source image does not support SubImage")
	}
	cropped := si.SubImage(image.Rect(x1, y1, x2, y2))

	var buf bytes.Buffer
	if err := png.Encode(&buf, cropped); err != nil {
		return 0, 0, "", fmt.Errorf("png encode: %w", err)
	}
	return x1, y1, base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// getImageDimensionsFromBase64 — admin.go 의 getImageDimensions 와 동일 로직 (별도 패키지 회피용 복제).
func getImageDimensionsFromBase64(b64 string) (int, int) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return 0, 0
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return 0, 0
	}
	return cfg.Width, cfg.Height
}

// buildGroundingPrompt — UGround-V1 / OS-Atlas 에서 학습된 표준 prompt template.
// Qwen2-VL 기반 grounding 모델들 (UGround, OS-Atlas, ShowUI, MAI-UI 등) 이 같은
// 형식으로 학습되어 있어 호환됨.
//
// 출처: huggingface.co/osunlp/UGround-V1-2B model card
func buildGroundingPrompt(description string) string {
	return fmt.Sprintf(`Your task is to help the user identify the precise coordinates (x, y) of a specific area/element/object on the screen based on a description.

- Your response should aim to point to the center or a representative point within the described area/element/object as accurately as possible.
- If the description is unclear or ambiguous, infer the most relevant area or element based on its likely context or purpose.
- Your answer should be a single string (x, y) corresponding to the point of the interest.

Description: %s

Answer:`, description)
}

// parseGroundingCoordinates — 다양한 grounding 모델 출력에서 (x, y) 추출.
// 정규화 좌표 자동 변환 (0-1 또는 0-1000 → 픽셀).
func parseGroundingCoordinates(text string, scrW, scrH int) (int, int, bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return 0, 0, false
	}

	// 1) JSON {"x":N,"y":N} — 가장 깔끔한 케이스
	if x, y, ok := tryParseJSONXY(text); ok {
		return rescaleIfNormalized(x, y, scrW, scrH), rescaleYIfNormalized(x, y, scrW, scrH), true
	}

	// 2) JSON {"point":[N,N]}
	if x, y, ok := tryParseJSONPoint(text); ok {
		return rescaleIfNormalized(x, y, scrW, scrH), rescaleYIfNormalized(x, y, scrW, scrH), true
	}

	// 3) JSON {"bbox":[x1,y1,x2,y2]} 또는 {"box":[x1,y1,x2,y2]} → midpoint
	if x, y, ok := tryParseJSONBbox(text); ok {
		return rescaleIfNormalized(x, y, scrW, scrH), rescaleYIfNormalized(x, y, scrW, scrH), true
	}

	// 4) OS-Atlas 토큰 <|box_start|>(x1,y1),(x2,y2)<|box_end|>
	if x, y, ok := tryParseOSAtlasBox(text); ok {
		return rescaleIfNormalized(x, y, scrW, scrH), rescaleYIfNormalized(x, y, scrW, scrH), true
	}

	// 5) Qwen-VL native <box>x1,y1,x2,y2</box> 또는 <point>x,y</point>, <click>x,y</click>
	if x, y, ok := tryParseAngleTags(text); ok {
		return rescaleIfNormalized(x, y, scrW, scrH), rescaleYIfNormalized(x, y, scrW, scrH), true
	}

	// 6) 텍스트에서 "(x, y)" 또는 "x, y" 첫 번째 숫자 쌍
	if x, y, ok := tryParseLooseNumbers(text); ok {
		return rescaleIfNormalized(x, y, scrW, scrH), rescaleYIfNormalized(x, y, scrW, scrH), true
	}

	return 0, 0, false
}

// rescaleIfNormalized — grounding 모델의 좌표 스케일을 자동 감지해서 픽셀로 변환.
//
// 휴리스틱:
//   • x, y 둘 다 ≤ 1.0  → 0~1 정규화 (드물지만 일부 모델). x * scrW.
//   • x, y 둘 다 ≤ 1000 → 0~1000 정규화 (UGround / OS-Atlas / Qwen-VL 표준).
//                          x / 1000 * scrW.
//   • 그 외             → 픽셀 직접 (Florence-2 류 등).
//
// 주의: y 와 x 가 같은 스케일이라는 가정 하에 양쪽이 모두 작아야 정규화로 판정.
// (한 쪽만 작으면 픽셀로 간주 → 잘못 rescale 방지)
func rescaleIfNormalized(x, y float64, scrW, _ int) int {
	if scrW <= 0 {
		return int(x)
	}
	if x >= 0 && y >= 0 && x <= 1.0 && y <= 1.0 {
		return int(x * float64(scrW))
	}
	if x > 1.0 && y > 1.0 && x <= 1000 && y <= 1000 {
		return int(x / 1000 * float64(scrW))
	}
	return int(x)
}

func rescaleYIfNormalized(x, y float64, _, scrH int) int {
	if scrH <= 0 {
		return int(y)
	}
	if x >= 0 && y >= 0 && x <= 1.0 && y <= 1.0 {
		return int(y * float64(scrH))
	}
	if x > 1.0 && y > 1.0 && x <= 1000 && y <= 1000 {
		return int(y / 1000 * float64(scrH))
	}
	return int(y)
}

func truncateForLog(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ── grounding response 파서들 ──────────────────────────────────────────

var (
	jsonXYRe       = regexp.MustCompile(`(?s)\{\s*"x"\s*:\s*(-?\d+(?:\.\d+)?)\s*,\s*"y"\s*:\s*(-?\d+(?:\.\d+)?)\s*\}`)
	jsonYXRe       = regexp.MustCompile(`(?s)\{\s*"y"\s*:\s*(-?\d+(?:\.\d+)?)\s*,\s*"x"\s*:\s*(-?\d+(?:\.\d+)?)\s*\}`)
	jsonPointRe    = regexp.MustCompile(`(?s)"(?:point|center|coords?)"\s*:\s*\[\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*\]`)
	jsonBboxRe     = regexp.MustCompile(`(?s)"(?:bbox|box|rect)"\s*:\s*\[\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*\]`)
	osAtlasBoxRe   = regexp.MustCompile(`<\|box_start\|>\s*\(?(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\)?\s*,?\s*\(?(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\)?\s*<\|box_end\|>`)
	angleBoxRe     = regexp.MustCompile(`<box>\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*</box>`)
	anglePointRe   = regexp.MustCompile(`<(?:point|click)>\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*</(?:point|click)>`)
	looseNumbersRe = regexp.MustCompile(`\(?\s*(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)\s*\)?`)
)

func tryParseJSONXY(text string) (float64, float64, bool) {
	if m := jsonXYRe.FindStringSubmatch(text); len(m) == 3 {
		x, err1 := strconv.ParseFloat(m[1], 64)
		y, err2 := strconv.ParseFloat(m[2], 64)
		if err1 == nil && err2 == nil {
			return x, y, true
		}
	}
	if m := jsonYXRe.FindStringSubmatch(text); len(m) == 3 {
		// 주의: 첫 캡처가 y, 두 번째가 x (이름 순서 반대)
		y, err1 := strconv.ParseFloat(m[1], 64)
		x, err2 := strconv.ParseFloat(m[2], 64)
		if err1 == nil && err2 == nil {
			return x, y, true
		}
	}
	return 0, 0, false
}

func tryParseJSONPoint(text string) (float64, float64, bool) {
	if m := jsonPointRe.FindStringSubmatch(text); len(m) == 3 {
		x, err1 := strconv.ParseFloat(m[1], 64)
		y, err2 := strconv.ParseFloat(m[2], 64)
		if err1 == nil && err2 == nil {
			return x, y, true
		}
	}
	return 0, 0, false
}

func tryParseJSONBbox(text string) (float64, float64, bool) {
	if m := jsonBboxRe.FindStringSubmatch(text); len(m) == 5 {
		x1, _ := strconv.ParseFloat(m[1], 64)
		y1, _ := strconv.ParseFloat(m[2], 64)
		x2, _ := strconv.ParseFloat(m[3], 64)
		y2, _ := strconv.ParseFloat(m[4], 64)
		return (x1 + x2) / 2, (y1 + y2) / 2, true
	}
	return 0, 0, false
}

func tryParseOSAtlasBox(text string) (float64, float64, bool) {
	if m := osAtlasBoxRe.FindStringSubmatch(text); len(m) == 5 {
		x1, _ := strconv.ParseFloat(m[1], 64)
		y1, _ := strconv.ParseFloat(m[2], 64)
		x2, _ := strconv.ParseFloat(m[3], 64)
		y2, _ := strconv.ParseFloat(m[4], 64)
		return (x1 + x2) / 2, (y1 + y2) / 2, true
	}
	return 0, 0, false
}

func tryParseAngleTags(text string) (float64, float64, bool) {
	if m := angleBoxRe.FindStringSubmatch(text); len(m) == 5 {
		x1, _ := strconv.ParseFloat(m[1], 64)
		y1, _ := strconv.ParseFloat(m[2], 64)
		x2, _ := strconv.ParseFloat(m[3], 64)
		y2, _ := strconv.ParseFloat(m[4], 64)
		return (x1 + x2) / 2, (y1 + y2) / 2, true
	}
	if m := anglePointRe.FindStringSubmatch(text); len(m) == 3 {
		x, _ := strconv.ParseFloat(m[1], 64)
		y, _ := strconv.ParseFloat(m[2], 64)
		return x, y, true
	}
	return 0, 0, false
}

func tryParseLooseNumbers(text string) (float64, float64, bool) {
	if m := looseNumbersRe.FindStringSubmatch(text); len(m) == 3 {
		x, err1 := strconv.ParseFloat(m[1], 64)
		y, err2 := strconv.ParseFloat(m[2], 64)
		if err1 == nil && err2 == nil {
			return x, y, true
		}
	}
	return 0, 0, false
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
	if headers == nil {
		headers = map[string]string{}
	}
	if headers["Content-Type"] == "" {
		headers["Content-Type"] = "application/json"
	}
	// Vision LLM은 크기가 큰 이미지 + 대형 모델(235B 등) 추론으로 60초는 부족.
	// 5분으로 넉넉히. 상위 http.Server write timeout 도 확인 필요.
	respRaw, status, err := s.dispatchLLMRequest(ctx, endpoint, headers, raw, 300*time.Second)
	if err != nil {
		return "", err
	}
	if status >= 300 {
		return "", fmt.Errorf("vision llm returned %d: %s", status, strings.TrimSpace(string(respRaw)))
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
	// When the org-llm-proxy is configured, credential resolution moves to
	// the cloud. Pass {{CREDENTIAL:*}} placeholders through unchanged so that
	// the cloud proxy (via boan-org-credential-gate) substitutes them right
	// before the upstream call. Plaintext never touches this host.
	if strings.TrimSpace(s.cfg.OrgLLMProxyURL) != "" && strings.TrimSpace(s.cfg.OrgLLMProxyToken) != "" {
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

	// 3. 최소 프롬프트 — decision/reason만
	systemPrompt := fmt.Sprintf(
		"You are a security guardrail. Constitution:\n%s\n\n"+
			"Reply ONLY with strict JSON: {\"decision\":\"allow|ask|block\",\"reason\":\"<10 words>\"}\n"+
			"Be concise. No thinking, no explanation.",
		strings.TrimSpace(constitution),
	)
	userPrompt := text

	// G2 전용 호출 — max_tokens=100 (작은 응답)
	out, fErr := s.callRegistryLLM(ctx, entry, systemPrompt, userPrompt, 100)
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
	if start := strings.Index(content, "{"); start >= 0 {
		if end := strings.LastIndex(content, "}"); end > start {
			_ = json.Unmarshal([]byte(content[start:end+1]), &parsed)
		}
	}
	if parsed.Decision == "" {
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
	return forwardViaOrgProxy(ctx, proxyURL, proxyToken, s.cfg.OrgID, endpoint, headers, body, timeout)
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

func forwardViaOrgProxy(ctx context.Context, proxyURL, proxyToken, orgID, endpoint string, headers map[string]string, body []byte, timeout time.Duration) ([]byte, int, error) {
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
