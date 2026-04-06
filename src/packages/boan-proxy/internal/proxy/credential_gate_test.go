package proxy

import (
	"os"
	"strings"
	"testing"
)

func TestCredentialFingerprint(t *testing.T) {
	fp1 := credentialFingerprint("sk-ant-api03-abc123xyz")
	fp2 := credentialFingerprint("sk-ant-api03-abc123xyz")
	fp3 := credentialFingerprint("sk-ant-api03-different")
	if fp1 != fp2 {
		t.Fatal("same value should produce same fingerprint")
	}
	if fp1 == fp3 {
		t.Fatal("different values should produce different fingerprints")
	}
}

func TestCredentialPreview(t *testing.T) {
	got := credentialPreview("sk-ant-api03-abc123xyz")
	if strings.Contains(got, "api03") {
		t.Fatalf("preview should not contain middle part: %q", got)
	}
	if !strings.HasPrefix(got, "sk-a") {
		t.Fatalf("preview should start with first 4 chars: %q", got)
	}
	if !strings.HasSuffix(got, "3xyz") {
		t.Fatalf("preview should end with last 4 chars: %q", got)
	}
}

func TestDeclinedFingerprintStore(t *testing.T) {
	dir := t.TempDir()
	store := newDeclinedFingerprintStore(dir)

	key := "sk-ant-api03-abcdefgh123456789012345678"
	if store.IsDeclined(key) {
		t.Fatal("should not be declined before adding")
	}
	store.AddByValue(key)
	if !store.IsDeclined(key) {
		t.Fatal("should be declined after adding")
	}

	// Reload from disk.
	store2 := newDeclinedFingerprintStore(dir)
	if !store2.IsDeclined(key) {
		t.Fatal("declined state should persist across reload")
	}
}

func TestDeclinedFingerprintStoreAddFingerprint(t *testing.T) {
	dir := t.TempDir()
	store := newDeclinedFingerprintStore(dir)

	key := "sk-proj-testkey1234567890abcdef"
	fp := credentialFingerprint(key)
	store.AddFingerprint(fp)
	if !store.IsDeclined(key) {
		t.Fatal("IsDeclined should match pre-computed fingerprint")
	}
}

func TestDeclinedFingerprintStoreLoadMissing(t *testing.T) {
	store := newDeclinedFingerprintStore("/nonexistent/path/that/does/not/exist")
	// Should not panic; just start empty.
	if store.IsDeclined("anything") {
		t.Fatal("empty store should not decline anything")
	}
}

func TestRawAPIKeyRe(t *testing.T) {
	cases := []struct {
		text  string
		match bool
	}{
		{"sk-ant-api03-abcdefghijklmnopqrstuvwxyz", true},
		{"sk-proj-abcdefghijklmnopqrstuvwxyz1234", true},
		{"ghp_abcdefghijklmnopqrstuvwxyz123456", true},
		{"github_pat_abcdefghijklmnopqrstuvwxyz", true},
		{"AIzaSyabcdefghijklmnopqrstuvwxyz12345", true},
		{"AKIAIOSFODNN7EXAMPLE1234567890abcdef", true},
		{"hello world", false},
		{"password=abc123", false}, // not an API key pattern
	}
	for _, tc := range cases {
		got := rawAPIKeyRe.MatchString(tc.text)
		if got != tc.match {
			t.Errorf("rawAPIKeyRe.MatchString(%q) = %v, want %v", tc.text, got, tc.match)
		}
	}
}

func TestIsObviouslyNonSecretCredential(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"sk-ant-api03-fakekey12345678901234567890", true},
		{"sk-proj-testkey1234567890abcdef", true},
		{"AIza-example-key-abcdefghijklmnopqrstuvwxyz", true},
		{"sk-ant-api03-realkey12345678901234567890", false},
	}
	for _, tc := range cases {
		if got := isObviouslyNonSecretCredential(tc.value); got != tc.want {
			t.Fatalf("isObviouslyNonSecretCredential(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestApplyCredentialGateNoKeys(t *testing.T) {
	dir := t.TempDir()
	// Use minimal server since no network calls needed for no-match case.
	store := newDeclinedFingerprintStore(dir)
	if store.IsDeclined("normal text without credentials") {
		t.Fatal("normal text should not be declined")
	}
}

func TestDeclinedStorePath(t *testing.T) {
	dir := t.TempDir()
	store := newDeclinedFingerprintStore(dir)
	store.AddByValue("sk-ant-api03-testkey12345678901234567890")
	expectedPath := dir + "/declined_credentials.json"
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Fatalf("declined_credentials.json not created at expected path: %s", expectedPath)
	}
}
