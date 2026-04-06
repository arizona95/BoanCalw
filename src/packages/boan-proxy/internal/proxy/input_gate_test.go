package proxy

import (
	"context"
	"testing"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/dlp"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/guardrail"
)

type stubGuardrail struct {
	resp *guardrail.EvaluateResponse
	err  error
}

func (s stubGuardrail) Evaluate(_ context.Context, _ string, _ guardrail.EvaluateRequest) (*guardrail.EvaluateResponse, error) {
	return s.resp, s.err
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

func TestEvaluateInputGateCreatesHITLApprovalForAskText(t *testing.T) {
	created := ""
	resp := evaluateInputGate(
		context.Background(),
		dlp.NewEngine("", ""),
		stubGuardrail{resp: &guardrail.EvaluateResponse{Decision: "ask", Reason: "needs owner review"}},
		"sds-corp",
		InputGateRequest{Mode: "text", Text: "upload internal runbook outside", SrcLevel: 3, DestLevel: 1},
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
