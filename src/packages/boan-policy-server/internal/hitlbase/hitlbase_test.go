package hitlbase

import (
	"context"
	"testing"

	"github.com/samsung-sds/boanclaw/boan-policy-server/internal/policy"
)

type stubReader struct{ p *policy.Policy }

func (s stubReader) Get(_ context.Context, _ string) (*policy.Policy, error) {
	return s.p, nil
}

func TestValidate_G1OnlyOneOp(t *testing.T) {
	cases := []struct {
		name string
		req  ChangeRequest
		ok   bool
	}{
		{"add-needs-newrule", ChangeRequest{Gate: GateG1, Op: OpAdd}, false},
		{"add-ok", ChangeRequest{Gate: GateG1, Op: OpAdd, NewRule: &G1Rule{Pattern: "abc"}}, true},
		{"add-bad-regex", ChangeRequest{Gate: GateG1, Op: OpAdd, NewRule: &G1Rule{Pattern: "[unclosed"}}, false},
		{"modify-needs-both", ChangeRequest{Gate: GateG1, Op: OpModify, NewRule: &G1Rule{Pattern: "abc"}}, false},
		{"modify-ok", ChangeRequest{Gate: GateG1, Op: OpModify, OldRule: &G1Rule{Pattern: "x"}, NewRule: &G1Rule{Pattern: "y"}}, true},
		{"remove-needs-old", ChangeRequest{Gate: GateG1, Op: OpRemove}, false},
		{"g1-with-paragraph-mismatch", ChangeRequest{Gate: GateG1, Op: OpAdd, NewRule: &G1Rule{Pattern: "x"}, Paragraph: &G2Paragraph{}}, false},
	}
	for _, c := range cases {
		err := c.req.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: ok=%v got err=%v", c.name, c.ok, err)
		}
	}
}

func TestValidate_G2ParagraphOnly(t *testing.T) {
	cases := []struct {
		name string
		req  ChangeRequest
		ok   bool
	}{
		{"add-needs-text", ChangeRequest{Gate: GateG2, Op: OpAdd, Paragraph: &G2Paragraph{}}, false},
		{"add-ok", ChangeRequest{Gate: GateG2, Op: OpAdd, Paragraph: &G2Paragraph{Text: "new para"}}, true},
		{"remove-ok-no-text", ChangeRequest{Gate: GateG2, Op: OpRemove, Paragraph: &G2Paragraph{Index: 0}}, true},
		{"g2-with-rule-mismatch", ChangeRequest{Gate: GateG2, Op: OpAdd, Paragraph: &G2Paragraph{Text: "x"}, NewRule: &G1Rule{Pattern: "x"}}, false},
	}
	for _, c := range cases {
		err := c.req.Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: ok=%v got err=%v", c.name, c.ok, err)
		}
	}
}

func TestSimulateG1_AddRule(t *testing.T) {
	p := &policy.Policy{}
	reader := stubReader{p: p}
	// truth: text "AKIA..." should be blocked; "hello" should not.
	decisions := func(_ string) []Decision {
		return []Decision{
			{ID: "d1", Text: "AKIA1234567890ABCDEF", Truth: "block"},
			{ID: "d2", Text: "hello world", Truth: "allow"},
			{ID: "d3", Text: "AKIA9999999999999999", Truth: "block"},
		}
	}
	h := New(reader, decisions)

	req := ChangeRequest{
		Gate: GateG1, Op: OpAdd,
		NewRule: &G1Rule{Pattern: "AKIA[A-Z0-9]{16}", Mode: "block"},
	}
	sim, err := h.SimulateG1(context.Background(), "org", req)
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	if sim.TT != 2 || sim.FF != 1 || sim.TF != 0 || sim.FT != 0 {
		t.Errorf("expected TT=2 FF=1 TF=0 FT=0, got %+v", sim)
	}
	if len(sim.FlippedToTrue) != 2 {
		t.Errorf("expected 2 flipped-to-true (caught after rule), got %d", len(sim.FlippedToTrue))
	}
}

func TestSimulateG1_RemoveCausesRegression(t *testing.T) {
	p := &policy.Policy{
		Guardrail: policy.GuardrailConfig{
			GT1Patterns: []policy.GT1Pattern{
				{Pattern: "AKIA[A-Z0-9]{16}", Mode: "block"},
			},
		},
	}
	reader := stubReader{p: p}
	decisions := func(_ string) []Decision {
		return []Decision{
			{ID: "d1", Text: "AKIA1234567890ABCDEF", Truth: "block"},
			{ID: "d2", Text: "hello", Truth: "allow"},
		}
	}
	h := New(reader, decisions)

	req := ChangeRequest{
		Gate: GateG1, Op: OpRemove,
		OldRule: &G1Rule{Pattern: "AKIA[A-Z0-9]{16}"},
	}
	sim, err := h.SimulateG1(context.Background(), "org", req)
	if err != nil {
		t.Fatalf("simulate: %v", err)
	}
	// after removal: d1 should-block but won't block (TF=1), d2 still allow (FF=1)
	if sim.TF != 1 || sim.FF != 1 {
		t.Errorf("expected TF=1 FF=1, got %+v", sim)
	}
	if len(sim.FlippedToFalse) != 1 || sim.FlippedToFalse[0].ID != "d1" {
		t.Errorf("expected d1 flipped to false, got %+v", sim.FlippedToFalse)
	}
}

func TestDiff_G2ParagraphMismatch(t *testing.T) {
	p := &policy.Policy{
		Guardrail: policy.GuardrailConfig{
			GT2Constitution: "first paragraph.\n\nsecond paragraph.",
		},
	}
	h := New(stubReader{p: p}, nil)
	req := ChangeRequest{
		Gate: GateG2, Op: OpModify,
		Paragraph: &G2Paragraph{Index: 0, Match: "WRONG", Text: "new text"},
	}
	if _, err := h.Diff(context.Background(), "org", req); err != ErrParagraphMismatch {
		t.Errorf("expected ErrParagraphMismatch, got %v", err)
	}
}

func TestDiff_G2OK(t *testing.T) {
	p := &policy.Policy{
		Guardrail: policy.GuardrailConfig{
			GT2Constitution: "first paragraph.\n\nsecond paragraph.",
		},
	}
	h := New(stubReader{p: p}, nil)
	req := ChangeRequest{
		Gate: GateG2, Op: OpModify,
		Paragraph: &G2Paragraph{Index: 1, Match: "second paragraph.", Text: "second paragraph (updated)."},
	}
	diff, err := h.Diff(context.Background(), "org", req)
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if diff.Before == "" || diff.After == "" {
		t.Errorf("expected before+after populated, got %+v", diff)
	}
}
