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

// ── 기본 Input Gate 테스트 ──────────────────────────────────────────────

func TestInputGate_AllowsSafeText(t *testing.T) {
	resp := evaluateInputGate(context.Background(), dlp.NewEngine("", ""), nil, "sds-corp", InputGateRequest{
		Mode: "text", Text: "dir C:\\Users\\Public",
	}, nil)
	if !resp.Allowed || resp.Action != "allow" {
		t.Fatalf("expected allow, got %+v", resp)
	}
}

func TestInputGate_AllowsNavigationKey(t *testing.T) {
	resp := evaluateInputGate(context.Background(), nil, nil, "sds-corp", InputGateRequest{
		Mode: "key", Key: "F2",
	}, nil)
	if !resp.Allowed {
		t.Fatalf("expected allow, got %+v", resp)
	}
}

func TestInputGate_AllowsSafeChord(t *testing.T) {
	resp := evaluateInputGate(context.Background(), nil, nil, "sds-corp", InputGateRequest{
		Mode: "chord", Key: "Ctrl+A",
	}, nil)
	if !resp.Allowed {
		t.Fatalf("expected allow, got %+v", resp)
	}
}

func TestInputGate_BlocksUnsupportedKey(t *testing.T) {
	resp := evaluateInputGate(context.Background(), nil, nil, "sds-corp", InputGateRequest{
		Mode: "key", Key: "Ctrl+V",
	}, nil)
	if resp.Allowed {
		t.Fatalf("expected block, got %+v", resp)
	}
}

func TestInputGate_ClipboardSyncBypassesGuardrail(t *testing.T) {
	resp := evaluateInputGate(
		context.Background(), nil,
		stubGuardrail{resp: &guardrail.EvaluateResponse{Decision: "block"}},
		"sds-corp",
		InputGateRequest{Mode: "clipboard_sync", Text: "copied", SrcLevel: 1, DestLevel: 3},
		nil,
	)
	if !resp.Allowed {
		t.Fatalf("clipboard sync should allow, got %+v", resp)
	}
}

// ── G1: 정규식 가드레일 (모든 사용자 무조건 적용) ──────────────────────

func TestG1_BlocksCredentialText(t *testing.T) {
	resp := evaluateInputGate(context.Background(), dlp.NewEngine("", ""), nil, "sds-corp", InputGateRequest{
		Mode: "text", Text: "export API_KEY=sk-ant-api03-abcdef1234567890",
	}, nil)
	if resp.Allowed || resp.Action != "credential_required" {
		t.Fatalf("G1 should block credential, got %+v", resp)
	}
}

func TestG1_BlocksCredentialPaste(t *testing.T) {
	resp := evaluateInputGate(context.Background(), dlp.NewEngine("", ""), nil, "sds-corp", InputGateRequest{
		Mode: "paste", Text: "Authorization: Bearer sk-ant-api03-abcdef1234567890",
	}, nil)
	if resp.Allowed || resp.Action != "credential_required" {
		t.Fatalf("G1 should block credential paste, got %+v", resp)
	}
}

func TestG1_BlocksEvenForAllowUser(t *testing.T) {
	// allow 사용자라도 G1(정규식)은 무조건 적용
	resp := evaluateInputGate(context.Background(), dlp.NewEngine("", ""), nil, "sds-corp", InputGateRequest{
		Mode: "text", Text: "password=sk-ant-api03-secret1234567890", AccessLevel: "allow",
		SrcLevel: 3, DestLevel: 1,
	}, nil)
	if resp.Allowed {
		t.Fatalf("G1 should block even allow user, got %+v", resp)
	}
}

// ── G2: 헌법+LLM 가드레일 (ask/deny 사용자만) ─────────────────────────

func TestG2_AllowUser_SkipsG2G3(t *testing.T) {
	// allow 사용자는 G1만 통과하면 G2/G3 건너뜀
	resp := evaluateInputGate(
		context.Background(), dlp.NewEngine("", ""),
		stubGuardrail{resp: &guardrail.EvaluateResponse{Decision: "block", Reason: "should not reach"}},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "hello world", SrcLevel: 3, DestLevel: 1, AccessLevel: "allow"},
		nil,
	)
	if !resp.Allowed {
		t.Fatalf("allow user should skip G2/G3, got %+v", resp)
	}
}

func TestG2_Allow(t *testing.T) {
	resp := evaluateInputGate(
		context.Background(), dlp.NewEngine("", ""),
		stubGuardrail{resp: &guardrail.EvaluateResponse{Decision: "allow"}},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "safe text", SrcLevel: 3, DestLevel: 1, AccessLevel: "ask"},
		nil,
	)
	if !resp.Allowed {
		t.Fatalf("G2 allow should pass, got %+v", resp)
	}
}

func TestG2_Block(t *testing.T) {
	resp := evaluateInputGate(
		context.Background(), dlp.NewEngine("", ""),
		stubGuardrail{resp: &guardrail.EvaluateResponse{Decision: "block", Reason: "constitution"}},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "send secrets", SrcLevel: 3, DestLevel: 1, AccessLevel: "ask"},
		nil,
	)
	if resp.Allowed || resp.Action != "block" {
		t.Fatalf("G2 block should block, got %+v", resp)
	}
}

// ── G3: Wiki 적응형 가드레일 (ask/deny 사용자만) ───────────────────────

func TestG2Ask_G3Allow(t *testing.T) {
	resp := evaluateInputGate(
		context.Background(), dlp.NewEngine("", ""),
		stubGuardrail{
			resp:     &guardrail.EvaluateResponse{Decision: "ask"},
			wikiResp: &guardrail.EvaluateResponse{Decision: "allow"},
		},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "borderline", SrcLevel: 3, DestLevel: 1, AccessLevel: "ask"},
		nil,
	)
	if !resp.Allowed {
		t.Fatalf("G2 ask + G3 allow should pass, got %+v", resp)
	}
}

func TestG2Ask_G3Block(t *testing.T) {
	resp := evaluateInputGate(
		context.Background(), dlp.NewEngine("", ""),
		stubGuardrail{
			resp:     &guardrail.EvaluateResponse{Decision: "ask"},
			wikiResp: &guardrail.EvaluateResponse{Decision: "block", Reason: "wiki blocked"},
		},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "suspicious", SrcLevel: 3, DestLevel: 1, AccessLevel: "ask"},
		nil,
	)
	if resp.Allowed || resp.Action != "block" {
		t.Fatalf("G2 ask + G3 block should block, got %+v", resp)
	}
}

func TestG2Ask_G3Ask_HumanApproval(t *testing.T) {
	created := false
	resp := evaluateInputGate(
		context.Background(), dlp.NewEngine("", ""),
		stubGuardrail{
			resp:     &guardrail.EvaluateResponse{Decision: "ask"},
			wikiResp: &guardrail.EvaluateResponse{Decision: "ask", Reason: "uncertain"},
		},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "gray area", SrcLevel: 3, DestLevel: 1, AccessLevel: "ask"},
		func(reason string, req InputGateRequest) string { created = true; return "apr-test" },
	)
	if resp.Allowed || resp.Action != "hitl_required" {
		t.Fatalf("G2 ask + G3 ask + ask user should require HITL, got %+v", resp)
	}
	if !created {
		t.Fatal("expected approval creation")
	}
}

func TestDenyUser_EarlyBlock_NoG2G3(t *testing.T) {
	// deny 사용자는 G2/G3 평가 없이 즉시 차단되어야 함 (downward flow 기준)
	called := false
	resp := evaluateInputGate(
		context.Background(), dlp.NewEngine("", ""),
		stubGuardrail{
			resp:     &guardrail.EvaluateResponse{Decision: "allow"}, // G2 가 allow 줘도 무시되어야 함
			wikiResp: &guardrail.EvaluateResponse{Decision: "allow"},
		},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "gray area", SrcLevel: 3, DestLevel: 1, AccessLevel: "deny"},
		func(reason string, req InputGateRequest) string { called = true; return "apr-deny" },
	)
	if resp.Allowed || resp.Action != "block" {
		t.Fatalf("deny user should be blocked immediately, got %+v", resp)
	}
	if resp.Tier != "access" {
		t.Fatalf("deny block tier should be 'access', got %q", resp.Tier)
	}
	if called {
		t.Fatal("deny user block should not create approval")
	}
}

// ── G1 + G2/G3 통합 시나리오 ───────────────────────────────────────────

func TestG1G2G3_CredentialBlocksBeforeG2(t *testing.T) {
	// G1이 credential 감지하면 G2/G3 호출 안 됨
	resp := evaluateInputGate(
		context.Background(), dlp.NewEngine("", ""),
		stubGuardrail{resp: &guardrail.EvaluateResponse{Decision: "allow"}}, // G2 호출 안 됨
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "sk-ant-api03-abcdef1234567890xxxx", SrcLevel: 3, DestLevel: 1, AccessLevel: "ask"},
		nil,
	)
	if resp.Action != "credential_required" {
		t.Fatalf("G1 should catch credential before G2, got %+v", resp)
	}
}
