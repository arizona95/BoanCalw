package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleTunnel_FailClosed(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodConnect, "http://abc.example.com:443", nil)
	req.Host = "abc.example.com:443"
	rr := httptest.NewRecorder()

	s.handleTunnel(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for raw CONNECT, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "raw CONNECT tunnel disabled") {
		t.Fatalf("unexpected body: %s", rr.Body.String())
	}
}
