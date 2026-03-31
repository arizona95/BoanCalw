package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	base := t.TempDir()
	return New(Config{
		Listen:  ":0",
		DataDir: filepath.Join(base, "data"),
		KeyDir:  filepath.Join(base, "keys"),
	})
}

func TestRegisterAndListUsers(t *testing.T) {
	srv := newTestServer(t)

	registerBody := map[string]string{
		"email":    "mock@sds.com",
		"password": "Password123!",
	}
	raw, _ := json.Marshal(registerBody)
	req := httptest.NewRequest(http.MethodPost, "/org/sds-corp/v1/users/register", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	srv.handleOrg(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/org/sds-corp/v1/users", nil)
	rec = httptest.NewRecorder()
	srv.handleOrg(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rec.Code, rec.Body.String())
	}

	var users []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &users); err != nil {
		t.Fatalf("unmarshal users: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("expected 1 user, got %d", len(users))
	}
	if users[0]["email"] != "mock@sds.com" {
		t.Fatalf("unexpected user: %+v", users[0])
	}
}

func TestCheckinBlocksOldVersion(t *testing.T) {
	srv := newTestServer(t)

	updateBody := map[string]any{
		"version_policy": map[string]any{
			"min_version": "1.2.0",
		},
	}
	raw, _ := json.Marshal(updateBody)
	req := httptest.NewRequest(http.MethodPost, "/org/sds-corp/v1/policy", bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	srv.handleOrg(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("update status=%d body=%s", rec.Code, rec.Body.String())
	}

	checkinBody := map[string]string{
		"instance_id":       "mock-1",
		"org_id":            "sds-corp",
		"boanclaw_version":  "1.0.0",
		"os":                "linux",
		"hostname":          "test-host",
		"user_id":           "mock@sds.com",
		"timestamp":         "2026-03-30T00:00:00Z",
		"sig":               "mock",
	}
	raw, _ = json.Marshal(checkinBody)
	req = httptest.NewRequest(http.MethodPost, "/org/sds-corp/v1/checkin", bytes.NewReader(raw))
	rec = httptest.NewRecorder()
	srv.handleOrg(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("checkin status=%d body=%s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal checkin: %v", err)
	}
	if resp["status"] != "update_required" {
		t.Fatalf("unexpected checkin response: %+v", resp)
	}
}
