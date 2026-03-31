package auth

import (
	"net/url"
	"strings"
	"testing"
)

func TestStateTokenRoundTrip(t *testing.T) {
	p := New(Config{JWTSecret: "test-secret"})
	in := &OAuthState{
		RedirectURL: "https://admin.example.com/api/auth/callback",
		ReturnTo:    "https://admin.example.com",
		IssuedAt:    12345,
	}

	token, err := p.CreateStateToken(in)
	if err != nil {
		t.Fatalf("create state token: %v", err)
	}

	out, err := p.ParseStateToken(token)
	if err != nil {
		t.Fatalf("parse state token: %v", err)
	}

	if out.RedirectURL != in.RedirectURL || out.ReturnTo != in.ReturnTo || out.IssuedAt != in.IssuedAt {
		t.Fatalf("state mismatch: got %+v want %+v", out, in)
	}
}

func TestAuthURLIncludesHostedDomainAndRedirect(t *testing.T) {
	p := New(Config{
		ClientID:            "client-id",
		AllowedEmailDomains: []string{"samsungsds.com"},
		JWTSecret:           "test-secret",
	})

	authURL := p.AuthURL("state-token", "https://admin.example.com/api/auth/callback")
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}

	q := u.Query()
	if q.Get("redirect_uri") != "https://admin.example.com/api/auth/callback" {
		t.Fatalf("unexpected redirect_uri: %q", q.Get("redirect_uri"))
	}
	if q.Get("hd") != "samsungsds.com" {
		t.Fatalf("unexpected hd: %q", q.Get("hd"))
	}
}

func TestValidateEmailDomain(t *testing.T) {
	p := New(Config{
		AllowedEmailDomains: []string{"samsungsds.com", "subsidiary.samsungsds.com"},
		JWTSecret:           "test-secret",
	})

	if !p.ValidateEmailDomain("user@samsungsds.com") {
		t.Fatal("expected samsungsds.com to be allowed")
	}
	if !p.ValidateEmailDomain("user@subsidiary.samsungsds.com") {
		t.Fatal("expected subsidiary domain to be allowed")
	}
	if p.ValidateEmailDomain("user@gmail.com") {
		t.Fatal("expected gmail.com to be rejected")
	}
}

func TestInvalidStateTokenRejected(t *testing.T) {
	p := New(Config{JWTSecret: "test-secret"})
	token, err := p.CreateStateToken(&OAuthState{RedirectURL: "https://admin.example.com"})
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	bad := token[:strings.LastIndex(token, ".")+1] + "tampered"
	if _, err := p.ParseStateToken(bad); err == nil {
		t.Fatal("expected tampered token to fail")
	}
}
