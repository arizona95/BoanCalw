package userstore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/roles"
)

type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
)

type User struct {
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash"`
	Role         string    `json:"role"`
	OrgID        string    `json:"org_id"`
	Status       Status    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

type Store struct {
	mu      sync.RWMutex
	users   map[string]*User
	dataDir string
}

var ErrExists   = errors.New("email already registered")
var ErrNotFound = errors.New("user not found")
var ErrBadPass  = errors.New("invalid password")
var ErrPending  = errors.New("account pending approval")
var ErrInvalidRole = errors.New("invalid role")

func New(dataDir string) (*Store, error) {
	s := &Store{users: make(map[string]*User), dataDir: dataDir}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	_ = s.load()
	return s, nil
}

func (s *Store) Register(email, password, orgID, role string, status Status) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[email]; ok {
		return nil, ErrExists
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	u := &User{
		Email:        email,
		PasswordHash: string(hash),
		Role:         string(roles.Normalize(roles.Role(role))),
		OrgID:        orgID,
		Status:       status,
		CreatedAt:    time.Now().UTC(),
	}
	s.users[email] = u
	_ = s.save()
	return u, nil
}

func (s *Store) Authenticate(email, password string) (*User, error) {
	s.mu.RLock()
	u, ok := s.users[email]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, ErrBadPass
	}
	if u.Status == StatusPending {
		return nil, ErrPending
	}
	return u, nil
}

func (s *Store) Get(email string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[email]
	if !ok {
		return nil, ErrNotFound
	}
	return u, nil
}

func (s *Store) List() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	return out
}

func (s *Store) SetRole(email, role string) error {
	if !roles.ValidString(role) {
		return ErrInvalidRole
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[email]
	if !ok {
		return ErrNotFound
	}
	u.Role = string(roles.Normalize(roles.Role(role)))
	return s.save()
}

func (s *Store) Approve(email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[email]
	if !ok {
		return ErrNotFound
	}
	u.Status = StatusApproved
	return s.save()
}

func (s *Store) Delete(email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[email]; !ok {
		return ErrNotFound
	}
	delete(s.users, email)
	return s.save()
}

func (s *Store) Upsert(email, orgID, role string, status Status) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	role = string(roles.Normalize(roles.Role(role)))
	if existing, ok := s.users[email]; ok {
		existing.OrgID = orgID
		existing.Role = role
		existing.Status = status
		if err := s.save(); err != nil {
			return nil, err
		}
		return existing, nil
	}

	u := &User{
		Email:     email,
		Role:      role,
		OrgID:     orgID,
		Status:    status,
		CreatedAt: time.Now().UTC(),
	}
	s.users[email] = u
	if err := s.save(); err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) load() error {
	b, err := os.ReadFile(filepath.Join(s.dataDir, "users.json"))
	if err != nil {
		return err
	}
	var list []*User
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, u := range list {
		s.users[u.Email] = u
	}
	return nil
}

func (s *Store) save() error {
	list := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dataDir, "users.json"), b, 0600)
}
