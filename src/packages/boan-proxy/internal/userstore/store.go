package userstore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
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

// AccessLevel — 사용자 정보 흐름 권한
// allow: 낮은 흐름 허용 + 모니터링만
// ask:   낮은 흐름에 가드레일 적용 (사전차단 + 모니터링)
// deny:  낮은 흐름 차단, 같은/높은 레벨만 허용
type AccessLevel string

const (
	AccessAllow AccessLevel = "allow"
	AccessAsk   AccessLevel = "ask"
	AccessDeny  AccessLevel = "deny"
)

func ValidAccessLevel(s string) bool {
	switch AccessLevel(s) {
	case AccessAllow, AccessAsk, AccessDeny:
		return true
	}
	return false
}

type User struct {
	Email         string       `json:"email"`
	PasswordHash  string       `json:"password_hash"`
	Role          string       `json:"role"`
	OrgID         string       `json:"org_id"`
	Status        Status       `json:"status"`
	AccessLevel   AccessLevel  `json:"access_level"`
	CreatedAt     time.Time    `json:"created_at"`
	Workstation   *Workstation `json:"workstation,omitempty"`
	RegisteredIP  string       `json:"registered_ip,omitempty"` // IP at registration — only this IP can login
}

type Workstation struct {
	Provider      string    `json:"provider"`
	Platform      string    `json:"platform"`
	Status        string    `json:"status"`
	DisplayName   string    `json:"display_name"`
	InstanceID    string    `json:"instance_id"`
	RemoteHost    string    `json:"remote_host,omitempty"`
	RemotePort    int       `json:"remote_port,omitempty"`
	RemoteUser    string    `json:"remote_user,omitempty"`
	RemotePass    string    `json:"remote_pass,omitempty"`
	Region        string    `json:"region,omitempty"`
	ConsoleURL    string    `json:"console_url,omitempty"`
	WebDesktopURL string    `json:"web_desktop_url,omitempty"`
	AssignedAt    time.Time `json:"assigned_at"`
}

type Store struct {
	mu      sync.RWMutex
	users   map[string]*User
	dataDir string
}

var ErrExists = errors.New("email already registered")
var ErrNotFound = errors.New("user not found")
var ErrBadPass = errors.New("invalid password")
var ErrPending = errors.New("account pending approval")
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
	return s.RegisterWithIP(email, password, orgID, role, status, "")
}

func (s *Store) RegisterWithIP(email, password, orgID, role string, status Status, registeredIP string) (*User, error) {
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
		AccessLevel:  AccessAsk,
		CreatedAt:    time.Now().UTC(),
		RegisteredIP: registeredIP,
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
	// 안정 정렬 — 소유자 최상단, 그 다음 CreatedAt → Email tiebreaker
	sort.SliceStable(out, func(i, j int) bool {
		iOwner := roles.Normalize(roles.Role(out[i].Role)) == roles.Owner
		jOwner := roles.Normalize(roles.Role(out[j].Role)) == roles.Owner
		if iOwner != jOwner {
			return iOwner // owner=true 가 먼저
		}
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].Email < out[j].Email
	})
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

func (s *Store) SetAccessLevel(email string, level AccessLevel) error {
	if !ValidAccessLevel(string(level)) {
		return errors.New("invalid access level")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[email]
	if !ok {
		return ErrNotFound
	}
	u.AccessLevel = level
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

func (s *Store) AssignWorkstation(email string, ws *Workstation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[email]
	if !ok {
		return ErrNotFound
	}
	u.Workstation = ws
	return s.save()
}

func (s *Store) Workstation(email string) (*Workstation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[email]
	if !ok {
		return nil, ErrNotFound
	}
	return u.Workstation, nil
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
		Email:       email,
		Role:        role,
		OrgID:       orgID,
		Status:      status,
		AccessLevel: AccessAsk,
		CreatedAt:   time.Now().UTC(),
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
