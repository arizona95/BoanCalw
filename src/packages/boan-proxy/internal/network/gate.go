package network

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type Endpoint struct {
	Host    string   `json:"host"`
	Ports   []int    `json:"ports"`
	Methods []string `json:"methods"`
}

type Policy struct {
	Endpoints []Endpoint `json:"endpoints"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type SignedPayload struct {
	Policy    json.RawMessage `json:"policy"`
	Signature string          `json:"signature"`
}

type Gate struct {
	mu        sync.RWMutex
	policy    *Policy
	policyURL string
	orgID     string
	client    *http.Client
	pubKey    ed25519.PublicKey
	lastFetch time.Time
	stats     struct {
		allowed atomic.Uint64
		blocked atomic.Uint64
	}
}

func NewGate(policyURL, orgID string) *Gate {
	return &Gate{
		policyURL: policyURL,
		orgID:     orgID,
		client:    &http.Client{Timeout: 10 * time.Second},
		policy:    &Policy{},
	}
}

func NewGateWithKey(policyURL, orgID string, pubKey ed25519.PublicKey) *Gate {
	g := NewGate(policyURL, orgID)
	g.pubKey = pubKey
	return g
}

func NewGateWithClient(policyURL, orgID string, client *http.Client) *Gate {
	return &Gate{
		policyURL: policyURL,
		orgID:     orgID,
		client:    client,
		policy:    &Policy{},
	}
}

func (g *Gate) StartRefresh(ctx context.Context, interval time.Duration) {
	go func() {
		g.refresh()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				g.refresh()
			}
		}
	}()
}

func (g *Gate) Allow(host, method string) error {
	return g.AllowWithPort(host, method, 0)
}

func (g *Gate) AllowWithPort(host, method string, port int) error {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if len(g.policy.Endpoints) == 0 {
		g.stats.blocked.Add(1)
		return fmt.Errorf("network gate: no policy loaded (fail-closed)")
	}
	bare, _, _ := net.SplitHostPort(host)
	if bare == "" {
		bare = host
	}
	for _, ep := range g.policy.Endpoints {
		if !matchHost(ep.Host, bare) {
			continue
		}
		if len(ep.Ports) > 0 && !containsPort(ep.Ports, port) {
			continue
		}
		if len(ep.Methods) == 0 {
			g.stats.allowed.Add(1)
			return nil
		}
		for _, m := range ep.Methods {
			if m == "*" || m == method {
				g.stats.allowed.Add(1)
				return nil
			}
		}
	}
	g.stats.blocked.Add(1)
	return fmt.Errorf("network gate: %s not in whitelist", host)
}

func AllowRequest(g *Gate, r *http.Request) error {
	return g.AllowWithPort(r.Host, r.Method, requestPort(r))
}

func (g *Gate) EndpointCount() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.policy.Endpoints)
}

func (g *Gate) LastFetch() time.Time {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.lastFetch
}

func (g *Gate) StatsAllowed() uint64 { return g.stats.allowed.Load() }
func (g *Gate) StatsBlocked() uint64 { return g.stats.blocked.Load() }

func (g *Gate) refresh() {
	if g.policyURL == "" {
		return
	}
	url := fmt.Sprintf("%s/org/%s/network-policy.json", g.policyURL, g.orgID)
	resp, err := g.client.Get(url)
	if err != nil {
		log.Printf("network gate: refresh failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("network gate: refresh returned status %d", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return
	}

	policy, err := g.decodePolicy(body)
	if err != nil {
		log.Printf("network gate: decode failed: %v", err)
		return
	}

	g.mu.Lock()
	g.policy = policy
	g.lastFetch = time.Now()
	g.mu.Unlock()
}

func (g *Gate) decodePolicy(body []byte) (*Policy, error) {
	var signed SignedPayload
	if err := json.Unmarshal(body, &signed); err == nil && len(signed.Policy) > 0 {
		if g.pubKey != nil {
			sig, err := base64.StdEncoding.DecodeString(signed.Signature)
			if err != nil {
				return nil, fmt.Errorf("decode signature: %w", err)
			}
			if !ed25519.Verify(g.pubKey, signed.Policy, sig) {
				return nil, fmt.Errorf("ed25519 signature verification failed")
			}
		}
		var p Policy
		if err := json.Unmarshal(signed.Policy, &p); err != nil {
			return nil, err
		}
		return &p, nil
	}
	var p Policy
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func matchHost(pattern, host string) bool {
	if pattern == "*" {
		return true
	}
	if pattern == host {
		return true
	}
	if len(pattern) > 2 && pattern[0] == '*' && pattern[1] == '.' {
		suffix := pattern[1:]
		if len(host) > len(suffix) && host[len(host)-len(suffix):] == suffix {
			return true
		}
	}
	return false
}

func containsPort(ports []int, port int) bool {
	if port == 0 {
		return false
	}
	for _, candidate := range ports {
		if candidate == port {
			return true
		}
	}
	return false
}

func requestPort(r *http.Request) int {
	if _, p, err := net.SplitHostPort(r.Host); err == nil {
		if port, err := net.LookupPort("tcp", p); err == nil {
			return port
		}
	}
	switch {
	case r.URL != nil && r.URL.Scheme == "https":
		return 443
	case r.TLS != nil:
		return 443
	default:
		return 80
	}
}
