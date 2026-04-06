package proxy

import (
	"strings"
	"testing"
)

func TestDetectRegistryCredentialKeys(t *testing.T) {
	curl := `curl -X POST https://api.anthropic.com/v1/messages -H "x-api-key: sk-ant-api03-1234567890abcdefghijklmnop" -H "content-type: application/json"`
	keys := detectRegistryCredentialKeys(curl)
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0] != "sk-ant-api03-1234567890abcdefghijklmnop" {
		t.Fatalf("unexpected key %q", keys[0])
	}
}

func TestSanitizeRegistryCurl(t *testing.T) {
	curl := `curl -X POST https://api.anthropic.com/v1/messages -H "x-api-key: sk-ant-api03-1234567890abcdefghijklmnop" -H "content-type: application/json"`
	out := sanitizeRegistryCurl(curl, "claude-sonnet")
	if strings.Contains(out, "sk-ant-api03-1234567890abcdefghijklmnop") {
		t.Fatalf("expected raw key removed: %q", out)
	}
	if !strings.Contains(out, "{{CREDENTIAL:claude-sonnet}}") {
		t.Fatalf("expected placeholder in sanitized curl: %q", out)
	}
}
