package policy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type UserStatus string

const (
	UserStatusPending  UserStatus = "pending"
	UserStatusApproved UserStatus = "approved"
)

type OrgUser struct {
	Email        string     `json:"email"`
	Name         string     `json:"name,omitempty"`
	PasswordHash string     `json:"password_hash,omitempty"`
	Role         string     `json:"role"`
	OrgID        string     `json:"org_id"`
	Status       UserStatus `json:"status"`
	AuthProvider string     `json:"auth_provider,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLoginAt  time.Time  `json:"last_login_at,omitempty"`
}

var (
	ErrUserExists   = errors.New("email already registered")
	ErrUserNotFound = errors.New("user not found")
)

func (s *Store) RegisterUser(orgID, email, password string) (*OrgUser, error) {
	return s.RegisterUserWithRole(orgID, email, password, "", UserStatus(""))
}

func (s *Store) RegisterUserWithRole(orgID, email, password, role string, status UserStatus) (*OrgUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.loadUsers(orgID)
	if err != nil {
		return nil, err
	}
	email = strings.TrimSpace(strings.ToLower(email))
	for _, u := range users {
		if u.Email == email {
			return nil, ErrUserExists
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	if role == "" {
		role = "user"
	}
	if status == "" {
		status = UserStatusPending
	}

	user := &OrgUser{
		Email:        email,
		PasswordHash: string(hash),
		Role:         role,
		OrgID:        orgID,
		Status:       status,
		AuthProvider: "password",
		CreatedAt:    time.Now().UTC(),
	}
	users = append(users, user)
	if err := s.saveUsers(orgID, users); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Store) UpsertSSOUser(orgID, email, name, role, provider string, status UserStatus) (*OrgUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.loadUsers(orgID)
	if err != nil {
		return nil, err
	}
	email = strings.TrimSpace(strings.ToLower(email))
	now := time.Now().UTC()
	if role == "" {
		role = "user"
	}
	if status == "" {
		status = UserStatusApproved
	}

	for _, u := range users {
		if u.Email != email {
			continue
		}
		u.Name = name
		if role != "" {
			u.Role = role
		}
		u.Status = status
		u.AuthProvider = provider
		u.LastLoginAt = now
		if err := s.saveUsers(orgID, users); err != nil {
			return nil, err
		}
		return u, nil
	}

	user := &OrgUser{
		Email:        email,
		Name:         name,
		Role:         role,
		OrgID:        orgID,
		Status:       status,
		AuthProvider: provider,
		CreatedAt:    now,
		LastLoginAt:  now,
	}
	users = append(users, user)
	if err := s.saveUsers(orgID, users); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Store) UpdateUser(orgID, email, role string, status UserStatus) (*OrgUser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.loadUsers(orgID)
	if err != nil {
		return nil, err
	}
	email = strings.TrimSpace(strings.ToLower(email))
	for _, u := range users {
		if u.Email != email {
			continue
		}
		if role != "" {
			u.Role = role
		}
		if status != "" {
			u.Status = status
		}
		u.LastLoginAt = time.Now().UTC()
		if err := s.saveUsers(orgID, users); err != nil {
			return nil, err
		}
		return u, nil
	}
	return nil, ErrUserNotFound
}

func (s *Store) DeleteUser(orgID, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.loadUsers(orgID)
	if err != nil {
		return err
	}
	email = strings.TrimSpace(strings.ToLower(email))
	filtered := make([]*OrgUser, 0, len(users))
	found := false
	for _, u := range users {
		if u.Email == email {
			found = true
			continue
		}
		filtered = append(filtered, u)
	}
	if !found {
		return ErrUserNotFound
	}
	return s.saveUsers(orgID, filtered)
}

func (s *Store) ListUsers(orgID string) ([]*OrgUser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadUsers(orgID)
}

func (s *Store) usersPath(orgID string) string {
	return filepath.Join(s.orgDir(orgID), "users.json")
}

func (s *Store) loadUsers(orgID string) ([]*OrgUser, error) {
	path := s.usersPath(orgID)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []*OrgUser{}, nil
		}
		return nil, err
	}
	var users []*OrgUser
	if err := json.Unmarshal(raw, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func (s *Store) saveUsers(orgID string, users []*OrgUser) error {
	raw, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.usersPath(orgID), raw, 0600)
}
