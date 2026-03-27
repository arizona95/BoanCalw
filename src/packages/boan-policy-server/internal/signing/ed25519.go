package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
)

type Signer struct {
	priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
}

func LoadOrCreate(privPath, pubPath string) (*Signer, error) {
	if _, err := os.Stat(privPath); os.IsNotExist(err) {
		return generate(privPath, pubPath)
	}
	return load(privPath, pubPath)
}

func (s *Signer) Sign(payload any) (string, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(s.priv, raw)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func (s *Signer) SignBytes(raw []byte) (string, error) {
	sig := ed25519.Sign(s.priv, raw)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func (s *Signer) Verify(payload any, sigB64 string) bool {
	raw, err := json.Marshal(payload)
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	return ed25519.Verify(s.Pub, raw, sig)
}

func generate(privPath, pubPath string) (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(privPath, []byte(base64.StdEncoding.EncodeToString(priv)), 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)), 0644); err != nil {
		return nil, err
	}
	return &Signer{priv: priv, Pub: pub}, nil
}

func load(privPath, pubPath string) (*Signer, error) {
	privRaw, err := os.ReadFile(privPath)
	if err != nil {
		return nil, err
	}
	pubRaw, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, err
	}
	priv, err := base64.StdEncoding.DecodeString(string(privRaw))
	if err != nil {
		return nil, err
	}
	pub, err := base64.StdEncoding.DecodeString(string(pubRaw))
	if err != nil {
		return nil, err
	}
	return &Signer{priv: ed25519.PrivateKey(priv), Pub: ed25519.PublicKey(pub)}, nil
}
