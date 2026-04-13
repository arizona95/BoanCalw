package policy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// GenerateUserToken — 32 바이트 랜덤 hex 토큰.
func GenerateUserToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// FindUserByToken — user_token 으로 user 조회. 없으면 nil.
// 토큰 기반 인증 시 middleware 가 이걸로 user status/role 확인.
func (s *Store) FindUserByToken(orgID, token string) (*OrgUser, error) {
	if token == "" {
		return nil, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	users, err := s.loadUsers(orgID)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.UserToken != "" && u.UserToken == token {
			return u, nil
		}
	}
	return nil, nil
}

type UserStatus string

const (
	UserStatusPending  UserStatus = "pending"
	UserStatusApproved UserStatus = "approved"
)

type OrgUser struct {
	Email        string       `json:"email"`
	Name         string       `json:"name,omitempty"`
	MachineID    string       `json:"machine_id,omitempty"`
	MachineName  string       `json:"machine_name,omitempty"`
	PasswordHash string       `json:"password_hash,omitempty"`
	Role         string       `json:"role"`
	OrgID        string       `json:"org_id"`
	Status       UserStatus   `json:"status"`
	AuthProvider string       `json:"auth_provider,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	LastLoginAt  time.Time    `json:"last_login_at,omitempty"`
	Workstation  *Workstation `json:"workstation,omitempty"`
	// RegisteredIP: TOFU (Trust On First Use) — 첫 로그인 시 자동 캡처, 이후 이 IP 에서만 로그인 허용.
	// owner/user 구분 없이 동일 패턴. GCP 중앙 저장 → 모든 배포에서 일관.
	RegisteredIP string `json:"registered_ip,omitempty"`
	// UserToken: 가입 시 발급되는 user-specific bearer token.
	// proxy 가 저장해서 이 user 가 속한 조직의 policy-server 요청에 Bearer 로 붙임.
	// pending 상태일 때도 유효 — 승인 상태 polling 용. 승인 후엔 일반 API 사용.
	UserToken string `json:"user_token,omitempty"`
}

type Workstation struct {
	Provider      string    `json:"provider"`
	Platform      string    `json:"platform"`
	Status        string    `json:"status"`
	DisplayName   string    `json:"display_name"`
	InstanceID    string    `json:"instance_id"`
	Region        string    `json:"region,omitempty"`
	ConsoleURL    string    `json:"console_url,omitempty"`
	WebDesktopURL string    `json:"web_desktop_url,omitempty"`
	AssignedAt    time.Time `json:"assigned_at"`
}

var (
	ErrUserExists   = errors.New("email already registered")
	ErrUserNotFound = errors.New("user not found")
)

func (s *Store) RegisterUser(orgID, email, password string) (*OrgUser, error) {
	return s.RegisterUserWithRole(orgID, email, password, "", UserStatus(""), "", "")
}

func (s *Store) RegisterUserWithRole(orgID, email, password, role string, status UserStatus, machineID, machineName string) (*OrgUser, error) {
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
		MachineID:    machineID,
		MachineName:  machineName,
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

func (s *Store) UpsertSSOUser(orgID, email, name, role, provider string, status UserStatus, machineID, machineName string) (*OrgUser, error) {
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
		if machineID != "" {
			u.MachineID = machineID
		}
		if machineName != "" {
			u.MachineName = machineName
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
		MachineID:    machineID,
		MachineName:  machineName,
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

func (s *Store) UpdateUser(orgID, email, role string, status UserStatus, workstation *Workstation, machineID, machineName string) (*OrgUser, error) {
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
		if workstation != nil {
			u.Workstation = workstation
		}
		if machineID != "" {
			u.MachineID = machineID
		}
		if machineName != "" {
			u.MachineName = machineName
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

// CheckOrCaptureLoginIP — TOFU IP 바인딩.
// user 없으면 (allowed=false, "user_not_found").
// user.RegisteredIP 비어있으면 clientIP 저장 후 allowed=true.
// user.RegisteredIP == clientIP → allowed=true.
// 아니면 allowed=false, "ip_mismatch".
func (s *Store) CheckOrCaptureLoginIP(orgID, email, clientIP string) (bool, string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.loadUsers(orgID)
	if err != nil {
		return false, "load_failed", "", err
	}
	email = strings.TrimSpace(strings.ToLower(email))
	for _, u := range users {
		if u.Email != email {
			continue
		}
		if u.RegisteredIP == "" {
			u.RegisteredIP = clientIP
			if err := s.saveUsers(orgID, users); err != nil {
				return false, "save_failed", "", err
			}
			return true, "captured", clientIP, nil
		}
		if u.RegisteredIP == clientIP {
			return true, "match", u.RegisteredIP, nil
		}
		return false, "ip_mismatch", u.RegisteredIP, nil
	}
	return false, "user_not_found", "", nil
}

// SetUserToken — user 의 UserToken 을 설정/재발급.
func (s *Store) SetUserToken(orgID, email, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	users, err := s.loadUsers(orgID)
	if err != nil {
		return err
	}
	email = strings.TrimSpace(strings.ToLower(email))
	for _, u := range users {
		if u.Email == email {
			u.UserToken = token
			return s.saveUsers(orgID, users)
		}
	}
	return ErrUserNotFound
}

// ResetUserIP — 관리자가 IP 재설정 (예: 사용자가 PC 교체 시).
func (s *Store) ResetUserIP(orgID, email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	users, err := s.loadUsers(orgID)
	if err != nil {
		return err
	}
	email = strings.TrimSpace(strings.ToLower(email))
	for _, u := range users {
		if u.Email == email {
			u.RegisteredIP = ""
			return s.saveUsers(orgID, users)
		}
	}
	return ErrUserNotFound
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
