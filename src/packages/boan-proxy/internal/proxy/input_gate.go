package proxy

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/dlp"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/guardrail"
)

type InputGateRequest struct {
	Mode        string `json:"mode"`
	Text        string `json:"text"`
	Key         string `json:"key,omitempty"`
	SrcLevel    int    `json:"src_level,omitempty"`
	DestLevel   int    `json:"dest_level,omitempty"`
	Flow        string `json:"flow,omitempty"`
	UserEmail   string `json:"user_email,omitempty"`
	AccessLevel string `json:"access_level,omitempty"` // allow / ask / deny
	LLMURL      string `json:"llm_url,omitempty"`      // registry security LLM URL
	LLMModel    string `json:"llm_model,omitempty"`    // registry security LLM model
	// G1 조직 정규식 패턴 + 모드. 이 값이 있으면 input_gate 가 이것만 사용.
	// 비어있으면 하드코딩 안전망 사용 (bootstrap / policy fetch 실패).
	// 컴파일 에러가 나는 패턴은 무시.
	G1Patterns []G1PatternRule `json:"g1_patterns,omitempty"`
}

// G1PatternRule — 정규식 + 매칭 시 동작. Mode:
//   "credential" — credential 치환 flow (기본 5개 패턴이 사용)
//   "block"      — 단순 차단 (프로젝트명/사내 도메인 등)
type G1PatternRule struct {
	Pattern string `json:"pattern"`
	Mode    string `json:"mode,omitempty"` // "credential" | "block", default "block"
}

// DefaultG1Patterns — 코드에 하드코딩된 기본 G1 정규식 패턴 (소스 문자열).
// 관리 콘솔의 Guardrail G1 섹션에 read-only 로 표시하기 위해 노출.
var DefaultG1Patterns = []string{
	`(?i)-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`,
	`(?i)\b(?:ghp|github_pat|sk-[a-z0-9]|AKIA|AIza)[A-Za-z0-9_\-]{8,}\b`,
	`(?i)\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`,
	`(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*\S+`,
	`(?i)\b(?:setx?|export)\s+[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY)[A-Z0-9_]*\s*[= ]\s*\S+`,
}

type InputGateResponse struct {
	Allowed        bool   `json:"allowed"`
	Action         string `json:"action"`
	Reason         string `json:"reason,omitempty"`
	// Tier — 최종 결정을 내린 tier. 관찰성 로그에 사용.
	//   G1         : 정규식 단계 (credential 패턴)
	//   G2         : 헌법 + LLM
	//   G3         : Wiki 적응형 LLM
	//   DLP        : DLP 엔진 (최종 fallback)
	//   access     : access_level=deny 차단
	//   key/chord/clipboard : non-text 모드
	Tier           string `json:"tier,omitempty"`
	NormalizedText string `json:"normalized_text,omitempty"`
	Key            string `json:"key,omitempty"`
	ApprovalID     string `json:"approval_id,omitempty"`
}

type GuardrailEvaluator interface {
	Evaluate(ctx context.Context, orgID string, req guardrail.EvaluateRequest) (*guardrail.EvaluateResponse, error)
	WikiEvaluate(ctx context.Context, orgID string, req guardrail.EvaluateRequest) (*guardrail.EvaluateResponse, error)
}

// LocalEvaluator — boan-proxy에서 직접 LLM을 호출하는 가드레일 평가 함수.
// nil이 아니면 우선 사용 (외부 policy-server 대신).
type LocalEvaluator func(ctx context.Context, orgID, text, mode string) (decision, reason, response string, err error)

var (
	credentialLikePatterns = compileDefaultG1Patterns()
	safeImmediateKeys      = map[string]struct{}{
		"Tab": {}, "Backspace": {}, "Delete": {}, "Escape": {}, "Enter": {},
		"ArrowUp": {}, "ArrowDown": {}, "ArrowLeft": {}, "ArrowRight": {},
		"Home": {}, "End": {}, "PageUp": {}, "PageDown": {}, "Insert": {},
		"F1": {}, "F2": {}, "F3": {}, "F4": {}, "F5": {}, "F6": {}, "F7": {}, "F8": {}, "F9": {}, "F10": {}, "F11": {}, "F12": {},
	}
	safeChords = map[string]struct{}{
		"Ctrl+A": {}, "Ctrl+C": {}, "Ctrl+X": {}, "Ctrl+Z": {}, "Ctrl+Y": {},
		"Meta+A": {}, "Meta+C": {}, "Meta+X": {}, "Meta+Z": {}, "Meta+Y": {},
	}
)

func compileDefaultG1Patterns() []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(DefaultG1Patterns))
	for _, p := range DefaultG1Patterns {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}

// compiledG1Rule — 컴파일된 G1 규칙 (regex + 매칭 시 동작 모드)
type compiledG1Rule struct {
	re   *regexp.Regexp
	mode string // "credential" | "block"
}

// compileG1Rules — 사용자 정의 G1 규칙을 컴파일 (에러 나는건 조용히 무시)
func compileG1Rules(rules []G1PatternRule) []compiledG1Rule {
	out := make([]compiledG1Rule, 0, len(rules))
	for _, r := range rules {
		pattern := strings.TrimSpace(r.Pattern)
		if pattern == "" {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		mode := strings.ToLower(strings.TrimSpace(r.Mode))
		if mode != "credential" && mode != "block" {
			mode = "block"
		}
		out = append(out, compiledG1Rule{re: re, mode: mode})
	}
	return out
}

func evaluateInputGate(
	ctx context.Context,
	eng *dlp.Engine,
	guardrailClient GuardrailEvaluator,
	orgID string,
	req InputGateRequest,
	createApproval func(reason string, req InputGateRequest) string,
) InputGateResponse {
	return evaluateInputGateWithLocal(ctx, eng, guardrailClient, nil, orgID, req, createApproval)
}

func evaluateInputGateWithLocal(
	ctx context.Context,
	eng *dlp.Engine,
	guardrailClient GuardrailEvaluator,
	localEval LocalEvaluator,
	orgID string,
	req InputGateRequest,
	createApproval func(reason string, req InputGateRequest) string,
) InputGateResponse {
	mode := strings.TrimSpace(strings.ToLower(req.Mode))
	switch mode {
	case "key":
		key := strings.TrimSpace(req.Key)
		if key == "" {
			return InputGateResponse{Allowed: false, Action: "block", Tier: "key", Reason: "missing key"}
		}
		if _, ok := safeImmediateKeys[key]; ok {
			return InputGateResponse{Allowed: true, Action: "allow", Tier: "key", Key: key}
		}
		return InputGateResponse{Allowed: false, Action: "block", Tier: "key", Reason: fmt.Sprintf("key %q requires secure input lane", key)}
	case "chord":
		key := strings.TrimSpace(req.Key)
		if key == "" {
			return InputGateResponse{Allowed: false, Action: "block", Tier: "chord", Reason: "missing chord"}
		}
		if _, ok := safeChords[key]; ok {
			return InputGateResponse{Allowed: true, Action: "allow", Tier: "chord", Key: key}
		}
		return InputGateResponse{Allowed: false, Action: "block", Tier: "chord", Reason: fmt.Sprintf("chord %q is not allowed", key)}
	case "clipboard_sync":
		text := strings.TrimSpace(req.Text)
		if text == "" {
			return InputGateResponse{Allowed: true, Action: "allow", Tier: "clipboard", Reason: "empty clipboard sync"}
		}
		return InputGateResponse{Allowed: true, Action: "allow", Tier: "clipboard", NormalizedText: req.Text, Reason: "clipboard sync observed"}
	case "text", "paste", "":
		text := req.Text
		if strings.TrimSpace(text) == "" {
			return InputGateResponse{Allowed: false, Action: "block", Tier: "G1", Reason: "empty input"}
		}

		// ══════════════════════════════════════════════════════════
		// G1: 정규식 가드레일 — 모든 사용자 무조건 적용 (allow 포함)
		//
		// 정책: req.G1Patterns 가 있으면 **그것만** 사용 (정책이 권위).
		// 없으면 안전망으로 하드코딩 기본 패턴 사용 (bootstrap / 정책 fetch 실패).
		// 기본 안전망 패턴은 모두 mode=credential 로 간주.
		// ══════════════════════════════════════════════════════════
		var g1Rules []compiledG1Rule
		if len(req.G1Patterns) > 0 {
			g1Rules = compileG1Rules(req.G1Patterns)
		} else {
			g1Rules = make([]compiledG1Rule, 0, len(credentialLikePatterns))
			for _, re := range credentialLikePatterns {
				g1Rules = append(g1Rules, compiledG1Rule{re: re, mode: "credential"})
			}
		}
		for _, rule := range g1Rules {
			if rule.re.MatchString(text) {
				// mode=credential → credential substitution flow
				// mode=block → 즉시 block (substitution 우회)
				action := "credential_required"
				reason := "[G1] credential-like pattern matched: " + rule.re.String()
				if rule.mode == "block" {
					action = "block"
					reason = "[G1] blocked by pattern: " + rule.re.String()
				}
				return InputGateResponse{
					Allowed: false,
					Action:  action,
					Tier:    "G1",
					Reason:  reason,
				}
			}
		}

		// 하향 흐름(S레벨 낮아짐) 체크
		isDownwardFlow := req.DestLevel > 0 && req.SrcLevel > 0 && req.DestLevel < req.SrcLevel

		// ══════════════════════════════════════════════════════════
		// Access level 조기 차단: deny 사용자는 하향 데이터 전송 전면 금지
		// G2/G3 가 "allow" 를 리턴해도 무시하고 무조건 block.
		// ══════════════════════════════════════════════════════════
		if isDownwardFlow && strings.ToLower(req.AccessLevel) == "deny" {
			return InputGateResponse{
				Allowed: false,
				Action:  "block",
				Tier:    "access",
				Reason:  "[access_level=deny] 사용자는 하향 데이터 전송이 금지됩니다",
			}
		}

		// G2/G3는 하향 흐름이고 guardrail client가 있을 때만
		if isDownwardFlow && guardrailClient != nil {
			grReq := guardrail.EvaluateRequest{
				Text: text, Mode: mode,
				UserEmail: req.UserEmail, AccessLevel: req.AccessLevel,
				LLMURL: req.LLMURL, LLMModel: req.LLMModel,
			}

			// allow 사용자: G1만 통과하면 G2/G3 건너뛰고 DLP로 직행
			if strings.ToLower(req.AccessLevel) != "allow" {

				// ══════════════════════════════════════════════════
				// G2: 헌법 + LLM 가드레일 — ask 사용자만 적용
				// boan-proxy(내 PC)에서 LLM 직접 호출 (localEval)
				// ══════════════════════════════════════════════════
				var g2Decision, g2Reason string
				if localEval != nil {
					d, r, _, e := localEval(ctx, orgID, text, mode)
					if e != nil {
						return InputGateResponse{Allowed: false, Action: "block", Tier: "G2", Reason: "[G2] " + r}
					}
					g2Decision, g2Reason = d, r
				} else {
					g2, err := guardrailClient.Evaluate(ctx, orgID, grReq)
					if err != nil {
						return InputGateResponse{Allowed: false, Action: "block", Tier: "G2", Reason: "[G2] guardrail LLM failed — fail-closed: " + err.Error()}
					}
					g2Decision, g2Reason = g2.Decision, g2.Reason
				}
				switch strings.ToLower(strings.TrimSpace(g2Decision)) {
				case "allow":
					// G2 통과 → DLP 검사로 (Tier 는 아래 DLP 결과로 갱신)
				case "block":
					return InputGateResponse{Allowed: false, Action: "block", Tier: "G2",
						Reason: "[G2] " + firstNonEmptyString(g2Reason, "constitution blocked")}
				case "ask":
					// ══════════════════════════════════════════════
					// G3: Wiki 적응형 가드레일 — ask 사용자만
					// 과거 결정을 학습한 자기진화 LLM
					// G3이 주기적으로 G1/G2를 자동 개정 제안
					// ══════════════════════════════════════════════
					g3, err := guardrailClient.WikiEvaluate(ctx, orgID, grReq)
					if err != nil {
						return InputGateResponse{Allowed: false, Action: "block", Tier: "G3", Reason: "[G3] wiki guardrail failed — fail-closed: " + err.Error()}
					}
					switch strings.ToLower(strings.TrimSpace(g3.Decision)) {
					case "allow":
						// G3 통과 → DLP 검사로
					case "block":
						return InputGateResponse{Allowed: false, Action: "block", Tier: "G3",
							Reason: "[G3] " + firstNonEmptyString(g3.Reason, "wiki guardrail blocked")}
					case "ask":
						// G3도 애매 → 인간(소유자) 승인 큐
						approvalID := ""
						if createApproval != nil {
							approvalID = createApproval(
								fmt.Sprintf("[G3 ask] %s", firstNonEmptyString(g3.Reason, "wiki guardrail requires review")),
								req,
							)
						}
						return InputGateResponse{
							Allowed:    false,
							Action:     "hitl_required",
							Tier:       "G3",
							Reason:     "[G3] " + firstNonEmptyString(g3.Reason, "human review required"),
							ApprovalID: approvalID,
						}
					}
				}
			}
		}

		if eng == nil {
			return InputGateResponse{Allowed: true, Action: "allow", Tier: "DLP", NormalizedText: text, Reason: "no DLP engine; allowed by default"}
		}

		decision, err := eng.Inspect(ctx, strings.NewReader(text))
		if err != nil {
			return InputGateResponse{Allowed: false, Action: "block", Tier: "DLP", Reason: "guardrail inspection failed"}
		}
		if decision == nil {
			return InputGateResponse{Allowed: false, Action: "block", Tier: "DLP", Reason: "guardrail returned no decision"}
		}

		switch decision.Action {
		case dlp.ActionAllow:
			return InputGateResponse{
				Allowed:        true,
				Action:         "allow",
				Tier:           "DLP",
				Reason:         firstNonEmptyString(decision.Reason, "[DLP] passed all tiers"),
				NormalizedText: decision.Body,
			}
		case dlp.ActionRedact:
			return InputGateResponse{
				Allowed: false,
				Action:  "redact_required",
				Tier:    "DLP",
				Reason:  "[DLP] sensitive input detected; use credential inject lane or rewrite",
			}
		default:
			return InputGateResponse{
				Allowed: false,
				Action:  "block",
				Tier:    "DLP",
				Reason:  "[DLP] critical input blocked by guardrail",
			}
		}
	default:
		return InputGateResponse{Allowed: false, Action: "block", Tier: "mode", Reason: fmt.Sprintf("unsupported input mode %q", req.Mode)}
	}
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
