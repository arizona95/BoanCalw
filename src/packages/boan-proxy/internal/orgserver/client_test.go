package orgserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientRegisterUser(t *testing.T) {
	var got map[string]string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/org/sds-corp/v1/users/register" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	c := New(ts.URL)
	if err := c.RegisterUser("sds-corp", "mock@sds.com", "Password123!"); err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}
	if got["email"] != "mock@sds.com" {
		t.Fatalf("unexpected request: %+v", got)
	}
}

func TestClientSyncSSOUser(t *testing.T) {
	var got map[string]string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/org/sds-corp/v1/users/sso-sync" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	c := New(ts.URL)
	if err := c.SyncSSOUser("sds-corp", "mock@sds.com", "Mock User", "owner", "google"); err != nil {
		t.Fatalf("SyncSSOUser: %v", err)
	}
	if got["provider"] != "google" || got["role"] != "owner" {
		t.Fatalf("unexpected request: %+v", got)
	}
}
