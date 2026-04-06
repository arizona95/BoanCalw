package network

import (
	"net/http/httptest"
	"testing"
)

func TestGateAllowWithPort_AllowsWhitelistedHostPortMethod(t *testing.T) {
	g := NewGate("", "test-org")
	g.policy = &Policy{
		Endpoints: []Endpoint{
			{Host: "abc.example.com", Ports: []int{443}, Methods: []string{"POST"}},
		},
	}

	if err := g.AllowWithPort("abc.example.com:443", "POST", 443); err != nil {
		t.Fatalf("expected allow, got error: %v", err)
	}
}

func TestGateAllowWithPort_BlocksDifferentHost(t *testing.T) {
	g := NewGate("", "test-org")
	g.policy = &Policy{
		Endpoints: []Endpoint{
			{Host: "abc.example.com", Ports: []int{443}, Methods: []string{"POST"}},
		},
	}

	if err := g.AllowWithPort("cde.example.com:443", "POST", 443); err == nil {
		t.Fatalf("expected cde.example.com to be blocked")
	}
}

func TestGateAllowWithPort_BlocksDifferentPort(t *testing.T) {
	g := NewGate("", "test-org")
	g.policy = &Policy{
		Endpoints: []Endpoint{
			{Host: "abc.example.com", Ports: []int{443}, Methods: []string{"POST"}},
		},
	}

	if err := g.AllowWithPort("abc.example.com:80", "POST", 80); err == nil {
		t.Fatalf("expected port 80 to be blocked")
	}
}

func TestAllowRequest_UsesDefaultHttpsPort(t *testing.T) {
	g := NewGate("", "test-org")
	g.policy = &Policy{
		Endpoints: []Endpoint{
			{Host: "abc.example.com", Ports: []int{443}, Methods: []string{"POST"}},
		},
	}

	req := httptest.NewRequest("POST", "https://abc.example.com/v1/messages", nil)
	if err := AllowRequest(g, req); err != nil {
		t.Fatalf("expected https request to be allowed on default 443: %v", err)
	}
}

func TestAllowRequest_BlocksUnlistedHttpDestination(t *testing.T) {
	g := NewGate("", "test-org")
	g.policy = &Policy{
		Endpoints: []Endpoint{
			{Host: "abc.example.com", Ports: []int{443}, Methods: []string{"POST"}},
		},
	}

	req := httptest.NewRequest("GET", "http://abc.example.com/status", nil)
	if err := AllowRequest(g, req); err == nil {
		t.Fatalf("expected http request on default port 80 to be blocked")
	}
}
