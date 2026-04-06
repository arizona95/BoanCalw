package network

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestDecodePolicyAcceptsSignedPayloadWithoutPubKey(t *testing.T) {
	g := NewGate("http://policy", "org")
	payload, _ := json.Marshal(map[string]any{
		"endpoints": []map[string]any{
			{"host": "abc.example.com", "ports": []int{443}, "methods": []string{"POST"}},
		},
	})
	doc, _ := json.Marshal(map[string]any{
		"policy":    json.RawMessage(payload),
		"signature": "ignored-without-pubkey",
	})

	p, err := g.decodePolicy(doc)
	if err != nil {
		t.Fatalf("decodePolicy returned error: %v", err)
	}
	if len(p.Endpoints) != 1 || p.Endpoints[0].Host != "abc.example.com" {
		t.Fatalf("unexpected endpoints: %+v", p.Endpoints)
	}
}

func TestDecodePolicyVerifiesSignedPayloadWithPubKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	g := NewGateWithKey("http://policy", "org", pub)
	payload, _ := json.Marshal(map[string]any{
		"endpoints": []map[string]any{
			{"host": "api.anthropic.com", "ports": []int{443}, "methods": []string{"POST"}},
		},
	})
	sig := ed25519.Sign(priv, payload)
	doc, _ := json.Marshal(map[string]any{
		"policy":    json.RawMessage(payload),
		"signature": base64.StdEncoding.EncodeToString(sig),
	})

	p, err := g.decodePolicy(doc)
	if err != nil {
		t.Fatalf("decodePolicy returned error: %v", err)
	}
	if len(p.Endpoints) != 1 || p.Endpoints[0].Host != "api.anthropic.com" {
		t.Fatalf("unexpected endpoints: %+v", p.Endpoints)
	}
}
