package proxy

import (
	"context"
	"strings"
	"testing"
)

func TestTranslateUpstreamToOpenAIOllamaThinkingFallback(t *testing.T) {
	raw := []byte(`{
		"model":"minimax-m2.7",
		"done":true,
		"done_reason":"stop",
		"message":{
			"role":"assistant",
			"content":"",
			"thinking":"Hello from thinking"
		},
		"prompt_eval_count":10,
		"eval_count":4
	}`)

	resp, err := translateUpstreamToOpenAI("minimax-m2.7", raw)
	if err != nil {
		t.Fatalf("translateUpstreamToOpenAI returned error: %v", err)
	}

	choices, ok := resp["choices"].([]map[string]any)
	if !ok || len(choices) != 1 {
		t.Fatalf("unexpected choices payload: %#v", resp["choices"])
	}
	msg, ok := choices[0]["message"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected message payload: %#v", choices[0]["message"])
	}
	if got := msg["content"]; got != "Hello from thinking" {
		t.Fatalf("expected thinking fallback, got %#v", got)
	}
}

func TestSanitizeCredentialReadableText(t *testing.T) {
	in := "password=abc123 token=xyz789"
	out := sanitizeCredentialReadableText(in)
	if strings.Contains(out, "abc123") || strings.Contains(out, "xyz789") {
		t.Fatalf("expected secrets to be masked, got %q", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Fatalf("expected redacted output, got %q", out)
	}
}

func TestSanitizePreservesHeaderName(t *testing.T) {
	cases := []struct {
		in      string
		wantIn  string // must appear in output
		wantOut string // must NOT appear in output
	}{
		{
			in:      `curl -H "x-api-key: secret-value-here" https://example.com`,
			wantIn:  "x-api-key: [REDACTED]",
			wantOut: "x-[REDACTED]",
		},
		{
			in:      `password=abc123`,
			wantIn:  "password=[REDACTED]",
			wantOut: "[REDACTED]=",
		},
		{
			in:      `export ANTHROPIC_API_KEY=sk-ant-real12345678901234`,
			wantIn:  "ANTHROPIC_API_KEY=[REDACTED]",
			wantOut: "export [REDACTED]",
		},
	}
	for _, tc := range cases {
		out := sanitizeCredentialReadableText(tc.in)
		if !strings.Contains(out, tc.wantIn) {
			t.Errorf("input %q: expected %q in output, got %q", tc.in, tc.wantIn, out)
		}
		if strings.Contains(out, tc.wantOut) {
			t.Errorf("input %q: unexpected %q in output, got %q", tc.in, tc.wantOut, out)
		}
	}
}

func TestSanitizeAllowsObviouslyFakeCredentialValues(t *testing.T) {
	in := `export ANTHROPIC_API_KEY=sk-ant-api03-fakekey123456789012345678901234`
	out := sanitizeCredentialReadableText(in)
	if out != in {
		t.Fatalf("expected fake/test credential to pass through unchanged, got %q", out)
	}
}

func TestSanitizeAllowsRegisteredPassthroughValues(t *testing.T) {
	in := `export ANTHROPIC_API_KEY=sk-ant-api03-custompassthrough12345678901234`
	out := sanitizeCredentialReadableTextWithKnown(in, nil, map[string]struct{}{
		"sk-ant-api03-custompassthrough12345678901234": {},
	})
	if out != in {
		t.Fatalf("expected registered passthrough value unchanged, got %q", out)
	}
}

func TestRedactValueInKeywordMatch(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"api-key: sk-ant-real123456789012", "api-key: [REDACTED]"},
		{"password=supersecret", "password=[REDACTED]"},
		{"token: mytoken123", "token: [REDACTED]"},
		{"export TOKEN=myvalue", "export TOKEN=[REDACTED]"},
	}
	for _, tc := range cases {
		got := redactValueInKeywordMatch(tc.in)
		if got != tc.want {
			t.Errorf("redactValueInKeywordMatch(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestResolveTemplateCredentialsSkipsRedactedPlaceholders(t *testing.T) {
	s := &Server{}
	// Generic redaction markers must be left as-is and must NOT cause an error.
	input := `{"content":"{{CREDENTIAL:REDACTED_SECRET_4}}"}`
	out, err := s.resolveTemplateCredentials(nil, input)
	if err != nil {
		t.Fatalf("expected no error for redacted placeholder, got: %v", err)
	}
	if out != input {
		t.Fatalf("expected placeholder preserved, got %q", out)
	}
}

func TestSanitizeCredentialReadableTextPreservesExplicitCredentialReference(t *testing.T) {
	in := `curl -H "x-api-key: {{CREDENTIAL:test-anthropic-key}}" https://api.anthropic.com/v1/messages`
	out := sanitizeCredentialReadableText(in)
	if !strings.Contains(out, "{{CREDENTIAL:test-anthropic-key}}") {
		t.Fatalf("expected explicit credential reference preserved, got %q", out)
	}
	if strings.Contains(out, "REDACTED_SECRET") {
		t.Fatalf("did not expect explicit credential reference to be redacted: %q", out)
	}
}

func TestSanitizeCredentialReadableTextWithKnown(t *testing.T) {
	in := "use sk-ant-api03-test1234567890abcdefghijklmnop for this request"
	out := sanitizeCredentialReadableTextWithKnown(in, map[string]string{
		"sk-ant-api03-test1234567890abcdefghijklmnop": "{{CREDENTIAL:test-anthropic-key}}",
	}, nil)
	if strings.Contains(out, "sk-ant-api03-test1234567890abcdefghijklmnop") {
		t.Fatalf("expected raw credential removed, got %q", out)
	}
	if !strings.Contains(out, "{{CREDENTIAL:test-anthropic-key}}") {
		t.Fatalf("expected known credential placeholder, got %q", out)
	}
}

func TestTranslateUpstreamToOpenAIMasksResponseSecrets(t *testing.T) {
	raw := []byte(`{
		"choices":[
			{
				"message":{
					"role":"assistant",
					"content":"password=abc123 token=xyz789"
				},
				"finish_reason":"stop"
			}
		]
	}`)

	resp, err := translateUpstreamToOpenAI("minimax-m2.7", raw)
	if err != nil {
		t.Fatalf("translateUpstreamToOpenAI returned error: %v", err)
	}

	choices, ok := resp["choices"].([]any)
	if !ok || len(choices) != 1 {
		t.Fatalf("unexpected choices payload: %#v", resp["choices"])
	}
	choice, ok := choices[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected choice payload: %#v", choices[0])
	}
	msg, ok := choice["message"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected message payload: %#v", choice["message"])
	}
	s := &Server{}
	resp = s.sanitizeOpenAIResponseForOrg(context.Background(), "sds-corp", resp)
	content, _ := msg["content"].(string)
	if strings.Contains(content, "abc123") || strings.Contains(content, "xyz789") {
		t.Fatalf("expected masked response content, got %q", content)
	}
	if !strings.Contains(content, "[REDACTED]") {
		t.Fatalf("expected redacted response content, got %q", content)
	}
}
