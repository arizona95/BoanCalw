// Package hitlbase is the single entry point for human-in-the-loop policy
// changes. Every guardrail tier (G1 regex, G2 constitution paragraph, …)
// pushes its proposed change through Request — never directly to the
// OrgPolicy store — so we get one place that:
//
//   1. enforces "one-unit-at-a-time" (G1 = exactly one rule
//      add|modify|remove; G2 = exactly one paragraph add|modify|remove).
//      No bulk re-writes — the operator must see and approve each delta
//      on its own.
//   2. computes the old↔new policy diff at approval time so the UI can
//      show the operator exactly what will change.
//   3. (G1 only) runs the proposed change against the entire stored
//      decision log as a "before vs after" simulation, returning a
//      TT/TF/FT/FF confusion matrix plus up-to-five examples that
//      flipped each direction. Operator sees the accuracy impact
//      before clicking Accept.
//
// Implementation note: hitlbase deliberately *does not* persist its own
// approval records; it composes on top of the existing approval queue
// the admin UI already polls. We just decorate each request with the
// diff/simulation payload so the operator's mental model is
// "approve THIS specific change", not "approve some opaque policy
// version bump."
package hitlbase

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/samsung-sds/boanclaw/boan-policy-server/internal/policy"
)

// GateID identifies which guardrail tier a change targets. Each tier has
// its own change unit type (G1Rule vs G2Paragraph) — passing the wrong one
// returns ErrChangeMismatch.
type GateID string

const (
	GateG1 GateID = "G1"
	GateG2 GateID = "G2"
)

// Op is the single mutation a Request can carry. Exactly one of
// Add/Modify/Remove applies; no batch.
type Op string

const (
	OpAdd    Op = "add"
	OpModify Op = "modify"
	OpRemove Op = "remove"
)

// G1Rule is one row in the G1 custom-patterns list. Captures everything
// the operator can see/edit in the UI for a single rule.
type G1Rule struct {
	Pattern     string `json:"pattern"`
	Replacement string `json:"replacement,omitempty"`
	Mode        string `json:"mode,omitempty"` // redact|block|credential
	Description string `json:"description,omitempty"`
}

// G2Paragraph is one paragraph (split by blank line) inside the
// Guardrail.GT2Constitution string. We address paragraphs by index because the
// raw text is operator-authored and has no stable IDs; the index is
// resolved against the *current* policy at apply time so concurrent edits
// fail cleanly instead of silently overwriting.
type G2Paragraph struct {
	Index int    `json:"index"`        // 0-based paragraph index inside constitution
	Text  string `json:"text"`         // new content (Add/Modify); ignored for Remove
	Match string `json:"match,omitempty"` // optional sanity-check: must equal current text at Index for Modify/Remove
}

// ChangeRequest describes one HITL-routed delta. Exactly one of
// G1RuleNew/G1RuleOld and G2Paragraph fields is populated, matching Gate.
type ChangeRequest struct {
	Gate       GateID
	Op         Op
	// G1 fields — Op=Add uses NewRule; Op=Modify uses OldRule (target) + NewRule
	// (replacement); Op=Remove uses only OldRule.
	OldRule *G1Rule
	NewRule *G1Rule
	// G2 fields — analogous semantics around Paragraph index/text.
	Paragraph *G2Paragraph
	// Caller-visible reason that shows up in the approval notification.
	Reason string
}

// PolicyDiff captures the human-readable difference between current and
// would-be policy. The UI renders this as the "what changes if you click
// Accept?" preview.
type PolicyDiff struct {
	Gate    GateID `json:"gate"`
	Summary string `json:"summary"`     // short label, e.g. "G1: add rule /sk-[A-Z]+/ (block)"
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
}

// Decision is one row in the stored decision log used as ground truth for
// the G1 simulation. Source labels (auto vs hitl) let us weight or filter
// later; for the simple confusion matrix we treat all entries as truth.
type Decision struct {
	ID       string
	Text     string
	Truth    string // "block" (should-be-blocked) | "allow" (should-pass)
	Source   string // "hitl" | "auto"
}

// Simulation is the G1 accuracy preview shown alongside the diff.
//   TT — was supposed to block, new ruleset blocks  → still correct
//   FF — was supposed to allow, new ruleset allows → still correct
//   TF — was supposed to block, new ruleset allows → REGRESSION (false negative)
//   FT — was supposed to allow, new ruleset blocks → REGRESSION (false positive)
// FlippedToFalse / FlippedToTrue list up to 5 examples for each regression
// direction so the operator can spot-check before approving.
type Simulation struct {
	TT             int        `json:"tt"`
	FF             int        `json:"ff"`
	TF             int        `json:"tf"` // regression: missed catches
	FT             int        `json:"ft"` // regression: new false alarms
	FlippedToFalse []Decision `json:"flipped_to_false,omitempty"` // 정탐→오탐
	FlippedToTrue  []Decision `json:"flipped_to_true,omitempty"`  // 오탐→정탐
}

// Errors surfaced to callers.
var (
	ErrChangeMismatch = errors.New("hitlbase: change payload does not match gate")
	ErrIndexOutOfRange = errors.New("hitlbase: paragraph index out of range")
	ErrParagraphMismatch = errors.New("hitlbase: paragraph match check failed (concurrent edit?)")
	ErrG1RuleNotFound = errors.New("hitlbase: target G1 rule not found in current policy")
)

// PolicyReader is the subset of the OrgPolicy backend that HITLbase needs
// to compute diffs/simulations. Keeping it as an interface lets the test
// suite stub it out without spinning up the full store.
type PolicyReader interface {
	Get(ctx context.Context, orgID string) (*policy.Policy, error)
}

// HITLbase is the single entry point. Construct one per Server and reuse.
type HITLbase struct {
	reader PolicyReader
	// decisions returns the corpus the G1 simulation compares against.
	// Plugged in by the server so tests can substitute synthetic logs.
	decisions func(orgID string) []Decision
}

func New(reader PolicyReader, decisions func(orgID string) []Decision) *HITLbase {
	return &HITLbase{reader: reader, decisions: decisions}
}

// Validate enforces the single-unit rule per gate. Callers should run this
// before queueing a request so the UI rejects malformed inputs early.
func (r ChangeRequest) Validate() error {
	switch r.Gate {
	case GateG1:
		if r.Paragraph != nil {
			return ErrChangeMismatch
		}
		switch r.Op {
		case OpAdd:
			if r.NewRule == nil || strings.TrimSpace(r.NewRule.Pattern) == "" {
				return errors.New("hitlbase: G1 add requires NewRule.Pattern")
			}
			if _, err := regexp.Compile(r.NewRule.Pattern); err != nil {
				return fmt.Errorf("hitlbase: G1 add invalid regex: %w", err)
			}
		case OpModify:
			if r.OldRule == nil || r.NewRule == nil {
				return errors.New("hitlbase: G1 modify requires OldRule + NewRule")
			}
			if _, err := regexp.Compile(r.NewRule.Pattern); err != nil {
				return fmt.Errorf("hitlbase: G1 modify invalid regex: %w", err)
			}
		case OpRemove:
			if r.OldRule == nil {
				return errors.New("hitlbase: G1 remove requires OldRule")
			}
		default:
			return fmt.Errorf("hitlbase: unknown op %q", r.Op)
		}
	case GateG2:
		if r.OldRule != nil || r.NewRule != nil {
			return ErrChangeMismatch
		}
		if r.Paragraph == nil {
			return errors.New("hitlbase: G2 requires Paragraph")
		}
		if r.Op == OpAdd || r.Op == OpModify {
			if strings.TrimSpace(r.Paragraph.Text) == "" {
				return errors.New("hitlbase: G2 add/modify requires non-empty Paragraph.Text")
			}
		}
	default:
		return fmt.Errorf("hitlbase: unknown gate %q", r.Gate)
	}
	return nil
}

// Diff computes the old↔new view of the policy under this request.
// Doesn't mutate state — the actual write happens only when an operator
// approves through OrgPolicy.Update.
func (h *HITLbase) Diff(ctx context.Context, orgID string, req ChangeRequest) (PolicyDiff, error) {
	if err := req.Validate(); err != nil {
		return PolicyDiff{}, err
	}
	current, err := h.reader.Get(ctx, orgID)
	if err != nil {
		return PolicyDiff{}, err
	}
	switch req.Gate {
	case GateG1:
		return g1Diff(current, req)
	case GateG2:
		return g2Diff(current, req)
	}
	return PolicyDiff{}, fmt.Errorf("hitlbase: unsupported gate %q", req.Gate)
}

// SimulateG1 runs the proposed change against the stored decision log and
// reports the confusion matrix + flip samples. G2/G3 simulation is out of
// scope here — paragraph-level effects need an actual LLM round-trip,
// which we don't want to bake into the synchronous approval path.
func (h *HITLbase) SimulateG1(ctx context.Context, orgID string, req ChangeRequest) (Simulation, error) {
	if req.Gate != GateG1 {
		return Simulation{}, fmt.Errorf("hitlbase: SimulateG1 only supports gate=G1")
	}
	if err := req.Validate(); err != nil {
		return Simulation{}, err
	}
	if h.decisions == nil {
		return Simulation{}, nil
	}
	current, err := h.reader.Get(ctx, orgID)
	if err != nil {
		return Simulation{}, err
	}
	oldRules := compileG1(current.Guardrail.GT1Patterns)
	newPatterns, err := applyG1(current.Guardrail.GT1Patterns, req)
	if err != nil {
		return Simulation{}, err
	}
	newRules := compileG1(newPatterns)

	decisions := h.decisions(orgID)
	sim := Simulation{}
	for _, d := range decisions {
		oldBlocks := matchesAny(oldRules, d.Text)
		newBlocks := matchesAny(newRules, d.Text)
		shouldBlock := strings.EqualFold(d.Truth, "block") || strings.EqualFold(d.Truth, "deny")

		// classify against new ruleset, but also detect flips vs old.
		switch {
		case shouldBlock && newBlocks:
			sim.TT++
		case !shouldBlock && !newBlocks:
			sim.FF++
		case shouldBlock && !newBlocks:
			sim.TF++
		case !shouldBlock && newBlocks:
			sim.FT++
		}
		if oldBlocks != newBlocks {
			if oldBlocks && !newBlocks {
				// 정탐(이전에 잡았던 것) → 오탐(이제 못 잡음 또는 통과)
				if shouldBlock {
					sim.FlippedToFalse = append(sim.FlippedToFalse, d)
				}
			} else if !oldBlocks && newBlocks {
				// 오탐(이전엔 통과) → 정탐 또는 새 오탐
				if shouldBlock {
					sim.FlippedToTrue = append(sim.FlippedToTrue, d)
				}
			}
		}
	}
	// stable order, then trim
	sort.SliceStable(sim.FlippedToFalse, func(i, j int) bool { return sim.FlippedToFalse[i].ID < sim.FlippedToFalse[j].ID })
	sort.SliceStable(sim.FlippedToTrue, func(i, j int) bool { return sim.FlippedToTrue[i].ID < sim.FlippedToTrue[j].ID })
	if len(sim.FlippedToFalse) > 5 {
		sim.FlippedToFalse = sim.FlippedToFalse[:5]
	}
	if len(sim.FlippedToTrue) > 5 {
		sim.FlippedToTrue = sim.FlippedToTrue[:5]
	}
	return sim, nil
}

// ────────────────────────────────────────────────────────────────────────
// internals — kept unexported so the package boundary stays small.
// ────────────────────────────────────────────────────────────────────────

type compiledRule struct {
	re      *regexp.Regexp
	mode    string
	pattern string
}

func compileG1(rules []policy.GT1Pattern) []compiledRule {
	out := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			continue
		}
		out = append(out, compiledRule{re: re, mode: r.Mode, pattern: r.Pattern})
	}
	return out
}

// matchesAny returns true if any rule with non-credential mode matches.
// credential mode is excluded because it doesn't represent a "block" call
// in production — it forwards to the credential filter.
func matchesAny(rules []compiledRule, text string) bool {
	for _, r := range rules {
		if r.mode == "credential" {
			continue
		}
		if r.re.MatchString(text) {
			return true
		}
	}
	return false
}

// applyG1 returns the new ruleset that would result from req without
// mutating the input slice. Errors when the target rule for modify/remove
// can't be found.
func applyG1(current []policy.GT1Pattern, req ChangeRequest) ([]policy.GT1Pattern, error) {
	out := append([]policy.GT1Pattern(nil), current...)
	switch req.Op {
	case OpAdd:
		out = append(out, policy.GT1Pattern{
			Pattern:     req.NewRule.Pattern,
			Replacement: req.NewRule.Replacement,
			Mode:        req.NewRule.Mode,
			Description: req.NewRule.Description,
		})
	case OpModify:
		idx := findG1Index(out, req.OldRule)
		if idx < 0 {
			return nil, ErrG1RuleNotFound
		}
		out[idx] = policy.GT1Pattern{
			Pattern:     req.NewRule.Pattern,
			Replacement: req.NewRule.Replacement,
			Mode:        req.NewRule.Mode,
			Description: req.NewRule.Description,
		}
	case OpRemove:
		idx := findG1Index(out, req.OldRule)
		if idx < 0 {
			return nil, ErrG1RuleNotFound
		}
		out = append(out[:idx], out[idx+1:]...)
	}
	return out, nil
}

func findG1Index(rules []policy.GT1Pattern, target *G1Rule) int {
	if target == nil {
		return -1
	}
	for i, r := range rules {
		if r.Pattern == target.Pattern {
			return i
		}
	}
	return -1
}

func g1Diff(p *policy.Policy, req ChangeRequest) (PolicyDiff, error) {
	switch req.Op {
	case OpAdd:
		return PolicyDiff{
			Gate:    GateG1,
			Summary: fmt.Sprintf("G1: add rule /%s/ (%s)", req.NewRule.Pattern, modeOrDefault(req.NewRule.Mode)),
			After:   fmt.Sprintf("pattern=%s replacement=%q mode=%s", req.NewRule.Pattern, req.NewRule.Replacement, modeOrDefault(req.NewRule.Mode)),
		}, nil
	case OpModify:
		if findG1Index(p.Guardrail.GT1Patterns, req.OldRule) < 0 {
			return PolicyDiff{}, ErrG1RuleNotFound
		}
		return PolicyDiff{
			Gate:    GateG1,
			Summary: fmt.Sprintf("G1: modify /%s/ → /%s/", req.OldRule.Pattern, req.NewRule.Pattern),
			Before:  fmt.Sprintf("pattern=%s replacement=%q mode=%s", req.OldRule.Pattern, req.OldRule.Replacement, modeOrDefault(req.OldRule.Mode)),
			After:   fmt.Sprintf("pattern=%s replacement=%q mode=%s", req.NewRule.Pattern, req.NewRule.Replacement, modeOrDefault(req.NewRule.Mode)),
		}, nil
	case OpRemove:
		if findG1Index(p.Guardrail.GT1Patterns, req.OldRule) < 0 {
			return PolicyDiff{}, ErrG1RuleNotFound
		}
		return PolicyDiff{
			Gate:    GateG1,
			Summary: fmt.Sprintf("G1: remove /%s/", req.OldRule.Pattern),
			Before:  fmt.Sprintf("pattern=%s replacement=%q mode=%s", req.OldRule.Pattern, req.OldRule.Replacement, modeOrDefault(req.OldRule.Mode)),
		}, nil
	}
	return PolicyDiff{}, fmt.Errorf("hitlbase: unsupported op %q", req.Op)
}

func g2Diff(p *policy.Policy, req ChangeRequest) (PolicyDiff, error) {
	paras := splitParagraphs(p.Guardrail.GT2Constitution)
	switch req.Op {
	case OpAdd:
		return PolicyDiff{
			Gate:    GateG2,
			Summary: fmt.Sprintf("G2: add paragraph at index %d", req.Paragraph.Index),
			After:   req.Paragraph.Text,
		}, nil
	case OpModify, OpRemove:
		if req.Paragraph.Index < 0 || req.Paragraph.Index >= len(paras) {
			return PolicyDiff{}, ErrIndexOutOfRange
		}
		if strings.TrimSpace(req.Paragraph.Match) != "" &&
			strings.TrimSpace(paras[req.Paragraph.Index]) != strings.TrimSpace(req.Paragraph.Match) {
			return PolicyDiff{}, ErrParagraphMismatch
		}
		out := PolicyDiff{Gate: GateG2, Before: paras[req.Paragraph.Index]}
		if req.Op == OpModify {
			out.Summary = fmt.Sprintf("G2: modify paragraph %d", req.Paragraph.Index)
			out.After = req.Paragraph.Text
		} else {
			out.Summary = fmt.Sprintf("G2: remove paragraph %d", req.Paragraph.Index)
		}
		return out, nil
	}
	return PolicyDiff{}, fmt.Errorf("hitlbase: unsupported op %q", req.Op)
}

// splitParagraphs treats one or more blank lines as paragraph separators.
// Trailing whitespace inside a paragraph is preserved so the operator's
// formatting (bullet lists, etc.) survives a modify cycle.
func splitParagraphs(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := regexp.MustCompile(`\n\s*\n+`).Split(s, -1)
	out := parts[:0]
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return out
}

func modeOrDefault(m string) string {
	if strings.TrimSpace(m) == "" {
		return "redact"
	}
	return strings.ToLower(strings.TrimSpace(m))
}
