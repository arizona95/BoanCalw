// Package devicekey generates, persists, and uses an Ed25519 keypair that
// identifies this local BoanClaw deployment. The private key stays on this
// host (TPM-sealed in a future iteration); the public key is exported so
// that cloud-side services (org-llm-proxy, credential-gate) can verify
// short-lived JWTs signed by this device.
//
// Threat model (P3): assume the host may be root-compromised. Device JWT
// does NOT protect against root on this host (root can read the key file
// and sign its own JWTs). It does:
//   - bind every outbound cloud call to a specific device identity → audit trail
//   - enable per-device revocation (rotate allowlist on cloud, invalidate this
//     device without having to re-key the whole org)
//   - reduce the blast radius of a leaked static bearer token (token alone
//     no longer authenticates; must also present device-signed JWT)
//
// A fully trusted device identity requires TPM sealing + remote attestation
// (deferred to P4+).
package devicekey

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Identity struct {
	DeviceID   string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// Load reads a persisted identity from keyPath, or generates + persists a
// new one if the file is missing. The file contains {device_id, priv_b64}.
// The device_id is a stable SHA-256 prefix of the public key.
func Load(keyPath string) (*Identity, error) {
	if keyPath == "" {
		return nil, errors.New("keyPath is required")
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, fmt.Errorf("mkdir: %w", err)
	}

	if raw, err := os.ReadFile(keyPath); err == nil {
		var persisted struct {
			DeviceID   string `json:"device_id"`
			PrivateKey string `json:"private_key_b64"`
		}
		if err := json.Unmarshal(raw, &persisted); err != nil {
			return nil, fmt.Errorf("decode device key file: %w", err)
		}
		priv, err := base64.StdEncoding.DecodeString(persisted.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("decode device private key: %w", err)
		}
		if len(priv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("device private key has wrong size %d", len(priv))
		}
		pk := ed25519.PrivateKey(priv)
		pub := pk.Public().(ed25519.PublicKey)
		return &Identity{
			DeviceID:   persisted.DeviceID,
			PrivateKey: pk,
			PublicKey:  pub,
		}, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(pub)
	deviceID := "dev-" + base64.RawURLEncoding.EncodeToString(hash[:6])

	out := struct {
		DeviceID   string `json:"device_id"`
		PrivateKey string `json:"private_key_b64"`
		PublicKey  string `json:"public_key_b64"`
		CreatedAt  string `json:"created_at"`
	}{
		DeviceID:   deviceID,
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	raw, _ := json.MarshalIndent(out, "", "  ")
	if err := os.WriteFile(keyPath, raw, 0o600); err != nil {
		return nil, fmt.Errorf("write device key file: %w", err)
	}
	return &Identity{DeviceID: deviceID, PrivateKey: priv, PublicKey: pub}, nil
}

// PublicKeyBase64 returns the base64-encoded public key, suitable for
// pinning on the server side.
func (id *Identity) PublicKeyBase64() string {
	if id == nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(id.PublicKey)
}

// SignJWT returns a compact JWS (EdDSA) with the given claims plus the
// standard iat/exp/jti that every cloud service enforces.
func (id *Identity) SignJWT(audience, orgID string, ttl time.Duration) (string, error) {
	if id == nil {
		return "", errors.New("nil device identity")
	}
	header := map[string]string{
		"alg": "EdDSA",
		"typ": "JWT",
		"kid": id.DeviceID,
	}
	now := time.Now().UTC()
	nonceRaw := make([]byte, 12)
	_, _ = rand.Read(nonceRaw)
	claims := map[string]any{
		"sub":       id.DeviceID,
		"aud":       audience,
		"org_id":    orgID,
		"iat":       now.Unix(),
		"exp":       now.Add(ttl).Unix(),
		"nbf":       now.Add(-30 * time.Second).Unix(),
		"jti":       base64.RawURLEncoding.EncodeToString(nonceRaw),
	}
	hRaw, _ := json.Marshal(header)
	cRaw, _ := json.Marshal(claims)
	segment := b64(hRaw) + "." + b64(cRaw)
	sig := ed25519.Sign(id.PrivateKey, []byte(segment))
	return segment + "." + b64(sig), nil
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// VerifyJWT parses and validates a compact JWS using one of the allowed
// public keys. Returns the claims on success.
//
// Validation:
//   - header.alg == EdDSA
//   - signature matches a key in allowedPubs
//   - exp is in the future
//   - aud matches expectedAud (if non-empty)
//   - iat is within skew of now
func VerifyJWT(token string, allowedPubs []ed25519.PublicKey, expectedAud string, skew time.Duration) (map[string]any, error) {
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
		Kid string `json:"kid"`
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
	_ = header.Kid // reserved for key lookup in future multi-key setups
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
			return nil, fmt.Errorf("decode pubkey %q: %w", short(p), err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("pubkey %q wrong size %d", short(p), len(raw))
		}
		out = append(out, ed25519.PublicKey(raw))
	}
	return out, nil
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}
