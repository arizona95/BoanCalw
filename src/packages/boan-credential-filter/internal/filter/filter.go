package filter

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/samsung-sds/boanclaw/boan-credential-filter/internal/kms"
)

type Status string

const (
	StatusOK             Status = "ok"
	StatusExpired        Status = "expired"
	StatusMissing        Status = "missing"
	StatusInvalidExpires Status = "invalid_expires"
	StatusUnresolvedRef  Status = "unresolved_ref"
)

type Credential struct {
	Role         string
	OrgID        string
	EncryptedKey []byte
	ExpiresAt    time.Time
}

type RegisterRequest struct {
	Role     string `json:"role"`
	Key      string `json:"key"`
	TTLHours int    `json:"ttl_hours"`
}

type CredentialResponse struct {
	Key       string `json:"key,omitempty"`
	Status    Status `json:"status"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type Store struct {
	mu    sync.RWMutex
	creds map[string]*Credential
	enc   *kms.LocalKMS
}

func NewStore(enc *kms.LocalKMS) *Store {
	return &Store{
		creds: make(map[string]*Credential),
		enc:   enc,
	}
}

func credKey(orgID, role string) string {
	return orgID + "/" + role
}

func (s *Store) Get(orgID, role string) (*CredentialResponse, error) {
	s.mu.RLock()
	c, ok := s.creds[credKey(orgID, role)]
	s.mu.RUnlock()

	if !ok {
		return &CredentialResponse{Status: StatusMissing}, nil
	}

	if c.ExpiresAt.IsZero() {
		return &CredentialResponse{Status: StatusInvalidExpires}, nil
	}

	if time.Now().After(c.ExpiresAt) {
		return &CredentialResponse{
			Status:    StatusExpired,
			ExpiresAt: c.ExpiresAt.Format(time.RFC3339),
		}, nil
	}

	decrypted, err := s.enc.Decrypt(c.EncryptedKey)
	if err != nil {
		return &CredentialResponse{Status: StatusUnresolvedRef}, nil
	}

	return &CredentialResponse{
		Key:       string(decrypted),
		Status:    StatusOK,
		ExpiresAt: c.ExpiresAt.Format(time.RFC3339),
	}, nil
}

func (s *Store) Register(orgID string, req *RegisterRequest) error {
	if req.Role == "" {
		return fmt.Errorf("role required")
	}
	if req.Key == "" {
		req.Key = GenerateAPIKey()
	}
	if req.TTLHours <= 0 {
		req.TTLHours = 24
	}

	encrypted, err := s.enc.Encrypt([]byte(req.Key))
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.creds[credKey(orgID, req.Role)] = &Credential{
		Role:         req.Role,
		OrgID:        orgID,
		EncryptedKey: encrypted,
		ExpiresAt:    time.Now().Add(time.Duration(req.TTLHours) * time.Hour),
	}
	s.mu.Unlock()
	return nil
}

type CredentialMeta struct {
	Role      string `json:"role"`
	OrgID     string `json:"org_id"`
	Status    Status `json:"status"`
	ExpiresAt string `json:"expires_at"`
}

func (s *Store) List(orgID string) []CredentialMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []CredentialMeta
	for _, c := range s.creds {
		if c.OrgID != orgID {
			continue
		}
		st := StatusOK
		if time.Now().After(c.ExpiresAt) {
			st = StatusExpired
		}
		out = append(out, CredentialMeta{
			Role:      c.Role,
			OrgID:     c.OrgID,
			Status:    st,
			ExpiresAt: c.ExpiresAt.Format(time.RFC3339),
		})
	}
	return out
}

func (s *Store) Revoke(orgID, role string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := credKey(orgID, role)
	if _, ok := s.creds[k]; ok {
		delete(s.creds, k)
		return true
	}
	return false
}

func GenerateAPIKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
