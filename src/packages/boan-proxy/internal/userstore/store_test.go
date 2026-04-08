package userstore

import (
	"os"
	"path/filepath"
	"testing"
)

func tempStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestAccessLevel_Default(t *testing.T) {
	s := tempStore(t)
	u, err := s.Register("a@test.com", "pass123", "org1", "user", StatusApproved)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if u.AccessLevel != AccessAsk {
		t.Errorf("default access_level = %q, want %q", u.AccessLevel, AccessAsk)
	}
}

func TestAccessLevel_SetAndGet(t *testing.T) {
	s := tempStore(t)
	s.Register("a@test.com", "pass123", "org1", "user", StatusApproved)

	for _, level := range []AccessLevel{AccessAllow, AccessDeny, AccessAsk} {
		if err := s.SetAccessLevel("a@test.com", level); err != nil {
			t.Fatalf("SetAccessLevel(%s): %v", level, err)
		}
		u, _ := s.Get("a@test.com")
		if u.AccessLevel != level {
			t.Errorf("after Set(%s), got %q", level, u.AccessLevel)
		}
	}
}

func TestAccessLevel_InvalidLevel(t *testing.T) {
	s := tempStore(t)
	s.Register("a@test.com", "pass123", "org1", "user", StatusApproved)

	if err := s.SetAccessLevel("a@test.com", "invalid"); err == nil {
		t.Error("expected error for invalid access level")
	}
}

func TestAccessLevel_UserNotFound(t *testing.T) {
	s := tempStore(t)
	if err := s.SetAccessLevel("nobody@test.com", AccessAllow); err != ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAccessLevel_Persistence(t *testing.T) {
	dir := t.TempDir()
	s1, _ := New(dir)
	s1.Register("a@test.com", "pass123", "org1", "user", StatusApproved)
	s1.SetAccessLevel("a@test.com", AccessDeny)

	// 새 Store 인스턴스로 다시 로드
	s2, _ := New(dir)
	u, _ := s2.Get("a@test.com")
	if u.AccessLevel != AccessDeny {
		t.Errorf("after reload, access_level = %q, want %q", u.AccessLevel, AccessDeny)
	}
}

func TestAccessLevel_UpsertDefault(t *testing.T) {
	s := tempStore(t)
	u, err := s.Upsert("b@test.com", "org1", "user", StatusApproved)
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if u.AccessLevel != AccessAsk {
		t.Errorf("upsert default access_level = %q, want %q", u.AccessLevel, AccessAsk)
	}
}

func TestAccessLevel_UpsertPreservesLevel(t *testing.T) {
	s := tempStore(t)
	s.Upsert("b@test.com", "org1", "user", StatusApproved)
	s.SetAccessLevel("b@test.com", AccessDeny)

	// Upsert 다시 호출 — access_level 이 유지되어야 함
	u, _ := s.Upsert("b@test.com", "org1", "user", StatusApproved)
	if u.AccessLevel != AccessDeny {
		t.Errorf("upsert should preserve access_level, got %q, want %q", u.AccessLevel, AccessDeny)
	}
}

func TestValidAccessLevel(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"allow", true},
		{"ask", true},
		{"deny", true},
		{"Allow", false},
		{"DENY", false},
		{"", false},
		{"block", false},
	}
	for _, tt := range tests {
		if got := ValidAccessLevel(tt.input); got != tt.want {
			t.Errorf("ValidAccessLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestAccessLevel_BackwardCompat(t *testing.T) {
	// 기존 users.json에 access_level 필드가 없는 경우 빈 문자열로 로드
	dir := t.TempDir()
	oldJSON := `[{"email":"old@test.com","password_hash":"","role":"user","org_id":"org1","status":"approved","created_at":"2026-01-01T00:00:00Z"}]`
	os.WriteFile(filepath.Join(dir, "users.json"), []byte(oldJSON), 0600)

	s, _ := New(dir)
	u, _ := s.Get("old@test.com")
	if u.AccessLevel != "" {
		t.Errorf("old user access_level should be empty, got %q", u.AccessLevel)
	}
	// SetAccessLevel로 설정 가능해야 함
	if err := s.SetAccessLevel("old@test.com", AccessAllow); err != nil {
		t.Fatalf("SetAccessLevel on old user: %v", err)
	}
	u, _ = s.Get("old@test.com")
	if u.AccessLevel != AccessAllow {
		t.Errorf("after set, got %q", u.AccessLevel)
	}
}
