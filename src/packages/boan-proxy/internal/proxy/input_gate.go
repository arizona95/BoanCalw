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
}

type InputGateResponse struct {
	Allowed        bool   `json:"allowed"`
	Action         string `json:"action"`
	Reason         string `json:"reason,omitempty"`
	NormalizedText string `json:"normalized_text,omitempty"`
	Key            string `json:"key,omitempty"`
	ApprovalID     string `json:"approval_id,omitempty"`
}

type GuardrailEvaluator interface {
	Evaluate(ctx context.Context, orgID string, req guardrail.EvaluateRequest) (*guardrail.EvaluateResponse, error)
	WikiEvaluate(ctx context.Context, orgID string, req guardrail.EvaluateRequest) (*guardrail.EvaluateResponse, error)
}

var (
	credentialLikePatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)\b(?:ghp|github_pat|sk-[a-z0-9]|AKIA|AIza)[A-Za-z0-9_\-]{8,}\b`),
		regexp.MustCompile(`(?i)\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`),
		regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\s*[:=]\s*\S+`),
		regexp.MustCompile(`(?i)\b(?:setx?|export)\s+[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_KEY|ACCESS_KEY)[A-Z0-9_]*\s*[= ]\s*\S+`),
	}
	safeImmediateKeys = map[string]struct{}{
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

func evaluateInputGate(
	ctx context.Context,
	eng *dlp.Engine,
	guardrailClient GuardrailEvaluator,
	orgID string,
	req InputGateRequest,
	createApproval func(reason string, req InputGateRequest) string,
) InputGateResponse {
	mode := strings.TrimSpace(strings.ToLower(req.Mode))
	switch mode {
	case "key":
		key := strings.TrimSpace(req.Key)
		if key == "" {
			return InputGateResponse{Allowed: false, Action: "block", Reason: "missing key"}
		}
		if _, ok := safeImmediateKeys[key]; ok {
			return InputGateResponse{Allowed: true, Action: "allow", Key: key}
		}
		return InputGateResponse{Allowed: false, Action: "block", Reason: fmt.Sprintf("key %q requires secure input lane", key)}
	case "chord":
		key := strings.TrimSpace(req.Key)
		if key == "" {
			return InputGateResponse{Allowed: false, Action: "block", Reason: "missing chord"}
		}
		if _, ok := safeChords[key]; ok {
			return InputGateResponse{Allowed: true, Action: "allow", Key: key}
		}
		return InputGateResponse{Allowed: false, Action: "block", Reason: fmt.Sprintf("chord %q is not allowed", key)}
	case "clipboard_sync":
		text := strings.TrimSpace(req.Text)
		if text == "" {
			return InputGateResponse{Allowed: true, Action: "allow", Reason: "empty clipboard sync"}
		}
		return InputGateResponse{Allowed: true, Action: "allow", NormalizedText: req.Text, Reason: "clipboard sync observed"}
	case "text", "paste", "":
		text := req.Text
		if strings.TrimSpace(text) == "" {
			return InputGateResponse{Allowed: false, Action: "block", Reason: "empty input"}
		}

		for _, pattern := range credentialLikePatterns {
			if pattern.MatchString(text) {
				return InputGateResponse{
					Allowed: false,
					Action:  "credential_required",
					Reason:  "credential-like input detected; use credential inject lane",
				}
			}
		}

		if req.DestLevel > 0 && req.SrcLevel > 0 && req.DestLevel < req.SrcLevel && guardrailClient != nil {
			grReq := guardrail.EvaluateRequest{
				Text: text, Mode: mode,
				UserEmail: req.UserEmail, AccessLevel: req.AccessLevel,
			}

			// ── Tier 1: 헌법 가드레일 ──
			tier1, err := guardrailClient.Evaluate(ctx, orgID, grReq)
			if err != nil {
				return InputGateResponse{Allowed: false, Action: "block", Reason: "tier1 guardrail failed: " + err.Error()}
			}
			switch strings.ToLower(strings.TrimSpace(tier1.Decision)) {
			case "allow":
				// Tier 1 통과 → DLP 검사로 진행
			case "block":
				return InputGateResponse{Allowed: false, Action: "block",
					Reason: firstNonEmptyString(tier1.Reason, "guardrail constitution blocked this input")}
			case "ask":
				// ── Tier 2: Wiki 가드레일 ──
				tier2, err := guardrailClient.WikiEvaluate(ctx, orgID, grReq)
				if err != nil {
					return InputGateResponse{Allowed: false, Action: "block", Reason: "tier2 wiki guardrail failed: " + err.Error()}
				}
				switch strings.ToLower(strings.TrimSpace(tier2.Decision)) {
				case "allow":
					// Tier 2 통과 → DLP 검사로 진행
				case "block":
					return InputGateResponse{Allowed: false, Action: "block",
						Reason: firstNonEmptyString(tier2.Reason, "wiki guardrail blocked this input")}
				case "ask":
					// ── Tier 3 분기: 사용자 access_level에 따라 ──
					if strings.ToLower(req.AccessLevel) == "allow" {
						// allow 사용자 → 통과 (모니터링만)
					} else {
						// ask/deny 사용자 → 인간 승인 큐
						approvalID := ""
						if createApproval != nil {
							approvalID = createApproval(
								fmt.Sprintf("[Tier2 ask] %s", firstNonEmptyString(tier2.Reason, "wiki guardrail requires review")),
								req,
							)
						}
						return InputGateResponse{
							Allowed:    false,
							Action:     "hitl_required",
							Reason:     firstNonEmptyString(tier2.Reason, "human review required"),
							ApprovalID: approvalID,
						}
					}
				}
			}
		}

		if eng == nil {
			return InputGateResponse{Allowed: true, Action: "allow", NormalizedText: text}
		}

		decision, err := eng.Inspect(ctx, strings.NewReader(text))
		if err != nil {
			return InputGateResponse{Allowed: false, Action: "block", Reason: "guardrail inspection failed"}
		}
		if decision == nil {
			return InputGateResponse{Allowed: false, Action: "block", Reason: "guardrail returned no decision"}
		}

		switch decision.Action {
		case dlp.ActionAllow:
			return InputGateResponse{
				Allowed:        true,
				Action:         "allow",
				Reason:         decision.Reason,
				NormalizedText: decision.Body,
			}
		case dlp.ActionRedact:
			return InputGateResponse{
				Allowed: false,
				Action:  "redact_required",
				Reason:  "sensitive input detected; use credential inject lane or rewrite",
			}
		default:
			return InputGateResponse{
				Allowed: false,
				Action:  "block",
				Reason:  "critical input blocked by guardrail",
			}
		}
	default:
		return InputGateResponse{Allowed: false, Action: "block", Reason: fmt.Sprintf("unsupported input mode %q", req.Mode)}
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
