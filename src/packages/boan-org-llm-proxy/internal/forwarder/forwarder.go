package forwarder

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ForwardRequest is the envelope sent by boan-proxy to this service.
// The caller fills in the exact HTTP request to make upstream; this
// service is the sole egress point for external LLM calls.
type ForwardRequest struct {
	Target    string            `json:"target"`
	Method    string            `json:"method"`
	Headers   map[string]string `json:"headers"`
	BodyB64   string            `json:"body_b64"`
	TimeoutMs int               `json:"timeout_ms"`
}

type ForwardResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	BodyB64 string            `json:"body_b64"`
}

type Forwarder struct {
	AllowedHostSuffixes []string
	DenyHostSuffixes    []string
	DefaultTimeout      time.Duration
	MaxTimeout          time.Duration
	client              *http.Client
}

func New(allowed, deny []string, defaultTimeout, maxTimeout time.Duration) *Forwarder {
	return &Forwarder{
		AllowedHostSuffixes: allowed,
		DenyHostSuffixes:    deny,
		DefaultTimeout:      defaultTimeout,
		MaxTimeout:          maxTimeout,
		client: &http.Client{
			Transport: &http.Transport{
				Proxy: nil,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
	}
}

func (f *Forwarder) Forward(ctx context.Context, req *ForwardRequest) (*ForwardResponse, error) {
	if strings.TrimSpace(req.Target) == "" {
		return nil, errors.New("target is required")
	}
	u, err := url.Parse(req.Target)
	if err != nil {
		return nil, fmt.Errorf("invalid target url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return nil, errors.New("target host is empty")
	}
	if !f.hostAllowed(host) {
		return nil, fmt.Errorf("host %q not in allowlist", host)
	}

	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodPost
	}

	var body []byte
	if req.BodyB64 != "" {
		body, err = base64.StdEncoding.DecodeString(req.BodyB64)
		if err != nil {
			return nil, fmt.Errorf("invalid body_b64: %w", err)
		}
	}

	timeout := f.DefaultTimeout
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
		if timeout > f.MaxTimeout {
			timeout = f.MaxTimeout
		}
	}

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(callCtx, method, req.Target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}
	if httpReq.Header.Get("Content-Type") == "" && len(body) > 0 {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	resp, err := f.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		if len(vs) > 0 {
			headers[k] = vs[0]
		}
	}

	return &ForwardResponse{
		Status:  resp.StatusCode,
		Headers: headers,
		BodyB64: base64.StdEncoding.EncodeToString(respBody),
	}, nil
}

func (f *Forwarder) hostAllowed(host string) bool {
	for _, d := range f.DenyHostSuffixes {
		if d != "" && (host == d || strings.HasSuffix(host, "."+d)) {
			return false
		}
	}
	if len(f.AllowedHostSuffixes) == 0 {
		return true
	}
	for _, a := range f.AllowedHostSuffixes {
		if a == "*" || host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

// EncodeError returns a JSON error body.
func EncodeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
