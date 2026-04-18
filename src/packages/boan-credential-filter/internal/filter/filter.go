package filter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	path  string
	// gate, when non-nil, makes this store a thin forwarder: all
	// register/get/list/revoke ops proxy to the cloud credential-gate and
	// NOTHING is persisted on this host. Local legacy storage is used only
	// when gate is nil.
	gate *GateClient
}

type persistedCredential struct {
	Role         string    `json:"role"`
	OrgID        string    `json:"org_id"`
	EncryptedKey []byte    `json:"encrypted_key"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func NewStore(enc *kms.LocalKMS, dataDir string) *Store {
	s := &Store{
		creds: make(map[string]*Credential),
		enc:   enc,
		path:  filepath.Join(dataDir, "credentials.json"),
	}
	if dataDir != "" {
		_ = os.MkdirAll(dataDir, 0700)
		_ = s.load()
	}
	return s
}

// WithGate switches the store into cloud-forwarding mode. All future
// register/get/list/revoke calls hit the remote boan-org-credential-gate;
// local plaintext/ciphertext never persists. Existing local entries remain
// readable as fallback (for migration).
func (s *Store) WithGate(gate *GateClient) *Store {
	s.gate = gate
	return s
}

func credKey(orgID, role string) string {
	return orgID + "/" + role
}

func (s *Store) Get(orgID, role string) (*CredentialResponse, error) {
	if s.gate != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		plain, err := s.gate.Resolve(ctx, orgID, role)
		if err != nil {
			return nil, err
		}
		if plain == "" {
			// fall through to legacy local lookup during migration window
		} else {
			return &CredentialResponse{Key: plain, Status: StatusOK}, nil
		}
	}

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

	if s.gate != nil {
		// Cloud-forwarding mode: write-through to credential-gate, NOTHING on disk.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.gate.Put(ctx, orgID, req.Role, req.Key)
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
	return s.save()
}

type CredentialMeta struct {
	Role      string `json:"role"`
	OrgID     string `json:"org_id"`
	Status    Status `json:"status"`
	ExpiresAt string `json:"expires_at"`
}

func (s *Store) List(orgID string) []CredentialMeta {
	if s.gate != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		remote, err := s.gate.List(ctx, orgID)
		if err == nil {
			out := make([]CredentialMeta, 0, len(remote))
			for _, m := range remote {
				out = append(out, CredentialMeta{
					Role:      m.Role,
					OrgID:     m.OrgID,
					Status:    StatusOK,
					ExpiresAt: "", // gate is version-based; no TTL
				})
			}
			sort.SliceStable(out, func(i, j int) bool { return out[i].Role < out[j].Role })
			return out
		}
		// On gate error, fall through to local list (migration fallback).
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CredentialMeta, 0)
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
	// 안정 정렬 — Role 기준 (매 조회마다 같은 순서)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Role < out[j].Role })
	return out
}

func (s *Store) Revoke(orgID, role string) bool {
	if s.gate != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.gate.Delete(ctx, orgID, role); err == nil {
			return true
		}
		// Fall through to local delete on gate error.
	}
	s.mu.Lock()
	k := credKey(orgID, role)
	if _, ok := s.creds[k]; ok {
		delete(s.creds, k)
		s.mu.Unlock()
		_ = s.save()
		return true
	}
	s.mu.Unlock()
	return false
}

func (s *Store) save() error {
	if s.path == "" {
		return nil
	}
	s.mu.RLock()
	items := make([]persistedCredential, 0, len(s.creds))
	for _, c := range s.creds {
		items = append(items, persistedCredential{
			Role:         c.Role,
			OrgID:        c.OrgID,
			EncryptedKey: c.EncryptedKey,
			ExpiresAt:    c.ExpiresAt,
		})
	}
	s.mu.RUnlock()
	raw, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, raw, 0600)
}

func (s *Store) load() error {
	if s.path == "" {
		return nil
	}
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var items []persistedCredential
	if err := json.Unmarshal(raw, &items); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range items {
		s.creds[credKey(item.OrgID, item.Role)] = &Credential{
			Role:         item.Role,
			OrgID:        item.OrgID,
			EncryptedKey: item.EncryptedKey,
			ExpiresAt:    item.ExpiresAt,
		}
	}
	return nil
}

func GenerateAPIKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}
