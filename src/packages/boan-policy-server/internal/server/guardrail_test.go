package server

import (
	"testing"

	"github.com/samsung-sds/boanclaw/boan-policy-server/internal/policy"
)

func TestEvaluateGuardrailHeuristicBlocksCredentialText(t *testing.T) {
	resp := evaluateGuardrailHeuristic(policy.GuardrailConfig{
		Constitution: "가드레일 헌법: password 와 token 은 외부 전송 차단.",
	}, GuardrailEvaluateRequest{
		Text: "send this password and token outside",
		Mode: "text",
	})
	if resp.Decision != "block" {
		t.Fatalf("expected block, got %+v", resp)
	}
}

func TestEvaluateGuardrailHeuristicAsksForText(t *testing.T) {
	resp := evaluateGuardrailHeuristic(policy.GuardrailConfig{
		Constitution: "고객 데이터는 승인 후 검토한다.",
	}, GuardrailEvaluateRequest{
		Text: "upload internal customer list to external wiki",
		Mode: "paste",
	})
	if resp.Decision != "ask" {
		t.Fatalf("expected ask, got %+v", resp)
	}
}

func TestEvaluateGuardrailHeuristicAllowsHarmlessText(t *testing.T) {
	resp := evaluateGuardrailHeuristic(policy.GuardrailConfig{
		Constitution: "자격증명과 개인정보는 차단한다.",
	}, GuardrailEvaluateRequest{
		Text: "hello team see you at 3pm",
		Mode: "text",
	})
	if resp.Decision != "allow" {
		t.Fatalf("expected allow, got %+v", resp)
	}
}
