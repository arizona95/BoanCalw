package proxy

import (
	"context"
	"testing"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/dlp"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/guardrail"
)

type stubGuardrail struct {
	resp     *guardrail.EvaluateResponse
	wikiResp *guardrail.EvaluateResponse
	err      error
}

func (s stubGuardrail) Evaluate(_ context.Context, _ string, _ guardrail.EvaluateRequest) (*guardrail.EvaluateResponse, error) {
	return s.resp, s.err
}

func (s stubGuardrail) WikiEvaluate(_ context.Context, _ string, _ guardrail.EvaluateRequest) (*guardrail.EvaluateResponse, error) {
	if s.wikiResp != nil {
		return s.wikiResp, s.err
	}
	return &guardrail.EvaluateResponse{Decision: "allow", Tier: 2}, nil
}

func TestEvaluateInputGateAllowsSafeText(t *testing.T) {
	resp := evaluateInputGate(context.Background(), dlp.NewEngine("", ""), nil, "sds-corp", InputGateRequest{
		Mode: "text",
		Text: "dir C:\\Users\\Public",
	}, nil)
	if !resp.Allowed {
		t.Fatalf("expected allowed response, got %+v", resp)
	}
	if resp.Action != "allow" {
		t.Fatalf("expected allow action, got %s", resp.Action)
	}
}

func TestEvaluateInputGateBlocksCredentialLikeText(t *testing.T) {
	resp := evaluateInputGate(context.Background(), dlp.NewEngine("", ""), nil, "sds-corp", InputGateRequest{
		Mode: "text",
		Text: "export API_KEY=sk-ant-api03-abcdef1234567890",
	}, nil)
	if resp.Allowed {
		t.Fatalf("expected blocked response, got %+v", resp)
	}
	if resp.Action != "credential_required" {
		t.Fatalf("expected credential_required action, got %s", resp.Action)
	}
}

func TestEvaluateInputGateBlocksCredentialLikePaste(t *testing.T) {
	resp := evaluateInputGate(context.Background(), dlp.NewEngine("", ""), nil, "sds-corp", InputGateRequest{
		Mode: "paste",
		Text: "Authorization: Bearer sk-ant-api03-abcdef1234567890",
	}, nil)
	if resp.Allowed {
		t.Fatalf("expected blocked paste response, got %+v", resp)
	}
	if resp.Action != "credential_required" {
		t.Fatalf("expected credential_required action, got %s", resp.Action)
	}
}

func TestEvaluateInputGateAllowsNavigationKey(t *testing.T) {
	resp := evaluateInputGate(context.Background(), nil, nil, "sds-corp", InputGateRequest{
		Mode: "key",
		Key:  "F2",
	}, nil)
	if !resp.Allowed {
		t.Fatalf("expected allowed key response, got %+v", resp)
	}
}

func TestEvaluateInputGateBlocksUnsupportedKeyChord(t *testing.T) {
	resp := evaluateInputGate(context.Background(), nil, nil, "sds-corp", InputGateRequest{
		Mode: "key",
		Key:  "Ctrl+V",
	}, nil)
	if resp.Allowed {
		t.Fatalf("expected blocked key response, got %+v", resp)
	}
}

func TestEvaluateInputGateAllowsSafeChord(t *testing.T) {
	resp := evaluateInputGate(context.Background(), nil, nil, "sds-corp", InputGateRequest{
		Mode: "chord",
		Key:  "Ctrl+A",
	}, nil)
	if !resp.Allowed {
		t.Fatalf("expected allowed chord response, got %+v", resp)
	}
}

func TestEvaluateInputGateAllowsClipboardSyncWithoutGuardrail(t *testing.T) {
	resp := evaluateInputGate(
		context.Background(),
		nil,
		stubGuardrail{resp: &guardrail.EvaluateResponse{Decision: "block", Reason: "should not run"}},
		"sds-corp",
		InputGateRequest{
			Mode:      "clipboard_sync",
			Text:      "copied from remote",
			SrcLevel:  1,
			DestLevel: 3,
		},
		nil,
	)
	if !resp.Allowed {
		t.Fatalf("expected clipboard sync allow response, got %+v", resp)
	}
}

// ── 3-Tier 가드레일 테스트 ─────────────────────────────────────────────────

func TestTier1Allow(t *testing.T) {
	resp := evaluateInputGate(
		context.Background(), dlp.NewEngine("", ""),
		stubGuardrail{resp: &guardrail.EvaluateResponse{Decision: "allow", Tier: 1}},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "hello world", SrcLevel: 3, DestLevel: 1},
		nil,
	)
	if !resp.Allowed {
		t.Fatalf("tier1 allow should pass, got %+v", resp)
	}
}

func TestTier1Block(t *testing.T) {
	resp := evaluateInputGate(
		context.Background(), dlp.NewEngine("", ""),
		stubGuardrail{resp: &guardrail.EvaluateResponse{Decision: "block", Reason: "constitution violation", Tier: 1}},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "send all secrets", SrcLevel: 3, DestLevel: 1},
		nil,
	)
	if resp.Allowed || resp.Action != "block" {
		t.Fatalf("tier1 block should block, got %+v", resp)
	}
}

func TestTier1Ask_Tier2Allow(t *testing.T) {
	resp := evaluateInputGate(
		context.Background(), dlp.NewEngine("", ""),
		stubGuardrail{
			resp:     &guardrail.EvaluateResponse{Decision: "ask", Tier: 1},
			wikiResp: &guardrail.EvaluateResponse{Decision: "allow", Tier: 2},
		},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "borderline content", SrcLevel: 3, DestLevel: 1},
		nil,
	)
	if !resp.Allowed {
		t.Fatalf("tier1 ask + tier2 allow should pass, got %+v", resp)
	}
}

func TestTier1Ask_Tier2Block(t *testing.T) {
	resp := evaluateInputGate(
		context.Background(), dlp.NewEngine("", ""),
		stubGuardrail{
			resp:     &guardrail.EvaluateResponse{Decision: "ask", Tier: 1},
			wikiResp: &guardrail.EvaluateResponse{Decision: "block", Reason: "wiki blocked", Tier: 2},
		},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "suspicious data", SrcLevel: 3, DestLevel: 1},
		nil,
	)
	if resp.Allowed || resp.Action != "block" {
		t.Fatalf("tier1 ask + tier2 block should block, got %+v", resp)
	}
}

func TestTier1Ask_Tier2Ask_AccessAllow(t *testing.T) {
	resp := evaluateInputGate(
		context.Background(), dlp.NewEngine("", ""),
		stubGuardrail{
			resp:     &guardrail.EvaluateResponse{Decision: "ask", Tier: 1},
			wikiResp: &guardrail.EvaluateResponse{Decision: "ask", Tier: 2},
		},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "gray area", SrcLevel: 3, DestLevel: 1, AccessLevel: "allow"},
		nil,
	)
	if !resp.Allowed {
		t.Fatalf("tier1 ask + tier2 ask + allow user should pass, got %+v", resp)
	}
}

func TestTier1Ask_Tier2Ask_AccessAsk(t *testing.T) {
	created := false
	resp := evaluateInputGate(
		context.Background(), dlp.NewEngine("", ""),
		stubGuardrail{
			resp:     &guardrail.EvaluateResponse{Decision: "ask", Tier: 1},
			wikiResp: &guardrail.EvaluateResponse{Decision: "ask", Reason: "wiki uncertain", Tier: 2},
		},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "gray area", SrcLevel: 3, DestLevel: 1, AccessLevel: "ask"},
		func(reason string, req InputGateRequest) string { created = true; return "apr-test" },
	)
	if resp.Allowed {
		t.Fatalf("tier1 ask + tier2 ask + ask user should require HITL, got %+v", resp)
	}
	if resp.Action != "hitl_required" {
		t.Fatalf("expected hitl_required, got %s", resp.Action)
	}
	if !created {
		t.Fatal("expected approval creation")
	}
}

func TestTier1Ask_Tier2Ask_AccessDeny(t *testing.T) {
	resp := evaluateInputGate(
		context.Background(), dlp.NewEngine("", ""),
		stubGuardrail{
			resp:     &guardrail.EvaluateResponse{Decision: "ask", Tier: 1},
			wikiResp: &guardrail.EvaluateResponse{Decision: "ask", Tier: 2},
		},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "gray area", SrcLevel: 3, DestLevel: 1, AccessLevel: "deny"},
		func(reason string, req InputGateRequest) string { return "apr-deny" },
	)
	if resp.Allowed {
		t.Fatalf("deny user should require HITL, got %+v", resp)
	}
	if resp.Action != "hitl_required" {
		t.Fatalf("expected hitl_required, got %s", resp.Action)
	}
}

// 기존 테스트 — Tier 1 ask 는 이제 Tier 2로 진행 (wiki default = allow)
func TestEvaluateInputGateCreatesHITLApprovalForAskText(t *testing.T) {
	created := ""
	resp := evaluateInputGate(
		context.Background(),
		dlp.NewEngine("", ""),
		stubGuardrail{
			resp:     &guardrail.EvaluateResponse{Decision: "ask", Reason: "needs owner review"},
			wikiResp: &guardrail.EvaluateResponse{Decision: "ask", Reason: "wiki also uncertain"},
		},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "upload internal runbook outside", SrcLevel: 3, DestLevel: 1, AccessLevel: "ask"},
		func(reason string, req InputGateRequest) string {
			created = reason + "|" + req.Text
			return "apr-1"
		},
	)
	if resp.Allowed {
		t.Fatalf("expected hitl response, got %+v", resp)
	}
	if resp.Action != "hitl_required" {
		t.Fatalf("expected hitl_required action, got %s", resp.Action)
	}
	if resp.ApprovalID != "apr-1" {
		t.Fatalf("expected approval id, got %+v", resp)
	}
	if created == "" {
		t.Fatal("expected approval callback to run")
	}
}

func TestEvaluateInputGateBlocksCriticalGuardrailDecision(t *testing.T) {
	resp := evaluateInputGate(
		context.Background(),
		dlp.NewEngine("", ""),
		stubGuardrail{resp: &guardrail.EvaluateResponse{Decision: "block", Reason: "constitution block"}},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "send customer credentials outside", SrcLevel: 3, DestLevel: 1},
		nil,
	)
	if resp.Allowed {
		t.Fatalf("expected blocked response, got %+v", resp)
	}
	if resp.Action != "block" {
		t.Fatalf("expected block action, got %s", resp.Action)
	}
}
