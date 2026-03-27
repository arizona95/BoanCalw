package promptguard

import (
	"strings"
	"unicode"
)

type Finding struct {
	Pattern string
	Match   string
}

var instructionOverrides = []string{
	"ignore previous instructions",
	"disregard above",
	"forget your",
	"new instructions",
	"system prompt",
	"you are now",
	"act as if",
}

var boundaryEscapes = []string{
	"```system",
	"### system",
	"[system]",
	"<system>",
	"<<sys>>",
}

var jailbreakKeywords = []string{
	"dan mode",
	"developer mode",
	"jailbreak",
	"do anything now",
}

func Check(text string) []Finding {
	normalized := normalizeFullwidth(text)
	lower := strings.ToLower(normalized)
	lowerOrig := strings.ToLower(text)

	var findings []Finding

	for _, p := range instructionOverrides {
		if idx := strings.Index(lowerOrig, p); idx != -1 {
			findings = append(findings, Finding{Pattern: "instruction_override", Match: text[idx : idx+len(p)]})
		} else if idx := strings.Index(lower, p); idx != -1 {
			findings = append(findings, Finding{Pattern: "instruction_override_homoglyph", Match: normalized[idx : idx+len(p)]})
		}
	}

	for _, p := range boundaryEscapes {
		if idx := strings.Index(lowerOrig, p); idx != -1 {
			findings = append(findings, Finding{Pattern: "boundary_escape", Match: text[idx : idx+len(p)]})
		} else if idx := strings.Index(lower, p); idx != -1 {
			findings = append(findings, Finding{Pattern: "boundary_escape_homoglyph", Match: normalized[idx : idx+len(p)]})
		}
	}

	for _, p := range jailbreakKeywords {
		if idx := strings.Index(lowerOrig, p); idx != -1 {
			findings = append(findings, Finding{Pattern: "jailbreak", Match: text[idx : idx+len(p)]})
		} else if idx := strings.Index(lower, p); idx != -1 {
			findings = append(findings, Finding{Pattern: "jailbreak_homoglyph", Match: normalized[idx : idx+len(p)]})
		}
	}

	return findings
}

func normalizeFullwidth(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= 0xFF01 && r <= 0xFF5E {
			b.WriteRune(rune(r - 0xFF01 + 0x21))
		} else {
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}
