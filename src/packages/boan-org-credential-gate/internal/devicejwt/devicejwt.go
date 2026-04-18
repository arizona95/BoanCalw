// Package devicejwt verifies Ed25519-signed JWTs from local BoanClaw
// deployments. Mirrors the sign-side in boan-proxy/internal/devicekey.
package devicejwt

import (
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Verify parses and validates a compact JWS using one of the allowed Ed25519
// public keys. Returns the claims on success. Validation: alg=EdDSA,
// signature matches a trusted key, exp not past, aud matches (if provided),
// iat within skew.
func Verify(token string, allowedPubs []ed25519.PublicKey, expectedAud string, skew time.Duration) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT structure")
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}
	if header.Alg != "EdDSA" {
		return nil, fmt.Errorf("unsupported alg %q", header.Alg)
	}

	claimsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode sig: %w", err)
	}
	signedSegment := []byte(parts[0] + "." + parts[1])

	verified := false
	for _, pub := range allowedPubs {
		if ed25519.Verify(pub, signedSegment, sig) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errors.New("signature not trusted by any allowed public key")
	}

	var claims map[string]any
	if err := json.Unmarshal(claimsRaw, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	expF, _ := claims["exp"].(float64)
	iatF, _ := claims["iat"].(float64)
	if expF == 0 {
		return nil, errors.New("missing exp")
	}
	now := time.Now().Unix()
	if int64(expF) < now-int64(skew/time.Second) {
		return nil, errors.New("token expired")
	}
	if iatF > 0 && int64(iatF) > now+int64(skew/time.Second) {
		return nil, errors.New("token iat in the future")
	}

	if expectedAud != "" {
		aud, _ := claims["aud"].(string)
		if !hmac.Equal([]byte(aud), []byte(expectedAud)) {
			return nil, fmt.Errorf("aud mismatch: got %q", aud)
		}
	}
	return claims, nil
}

// ParseAllowedPubs decodes a comma-separated list of base64 Ed25519 public
// keys. Blank entries are ignored.
func ParseAllowedPubs(csv string) ([]ed25519.PublicKey, error) {
	out := []ed25519.PublicKey{}
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			return nil, fmt.Errorf("decode pubkey: %w", err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("pubkey wrong size %d", len(raw))
		}
		out = append(out, ed25519.PublicKey(raw))
	}
	return out, nil
}
