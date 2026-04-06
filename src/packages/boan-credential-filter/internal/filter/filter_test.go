package filter

import (
	"path/filepath"
	"testing"

	"github.com/samsung-sds/boanclaw/boan-credential-filter/internal/kms"
)

func TestStorePersistsCredentials(t *testing.T) {
	dir := t.TempDir()
	enc, err := kms.New(filepath.Join(dir, "aes.key"))
	if err != nil {
		t.Fatalf("kms.New: %v", err)
	}

	store := NewStore(enc, dir)
	if err := store.Register("sds-corp", &RegisterRequest{
		Role:     "minimax-m2.7-cloud-apikey",
		Key:      "secret-value-123456",
		TTLHours: 24,
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	reloaded := NewStore(enc, dir)
	got, err := reloaded.Get("sds-corp", "minimax-m2.7-cloud-apikey")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != StatusOK {
		t.Fatalf("expected status ok, got %s", got.Status)
	}
	if got.Key != "secret-value-123456" {
		t.Fatalf("expected persisted key, got %q", got.Key)
	}
}
