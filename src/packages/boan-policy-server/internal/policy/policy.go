package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type NetworkEndpoint struct {
	Host    string   `json:"host"`
	Ports   []int    `json:"ports,omitempty"`
	Methods []string `json:"methods,omitempty"`
}

type DLPRule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	SLevel  int    `json:"slevel"`
}

type RBACRole struct {
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	SLevel      int      `json:"slevel"`
}

type RBACConfig struct {
	Roles         []RBACRole `json:"roles"`
	DefaultRole   string     `json:"default_role"`
	EnforceStrict bool       `json:"enforce_strict"`
}

type VersionPolicy struct {
	MinVersion      string   `json:"min_version,omitempty"`
	BlockedVersions []string `json:"blocked_versions,omitempty"`
	UpdateChannel   string   `json:"update_channel,omitempty"`
}

type SSOProvider struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Enabled     bool   `json:"enabled"`
	Configured  bool   `json:"configured"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

type OrgSettings struct {
	OrgName        string        `json:"org_name,omitempty"`
	AllowedSSO     []SSOProvider `json:"allowed_sso,omitempty"`
	AllowedDomains []string      `json:"allowed_domains,omitempty"` // SSO 허용 이메일 도메인
	AdminEmails    []string      `json:"admin_emails,omitempty"`
	SeatLimit      int           `json:"seat_limit,omitempty"`
	GCPOrgID       string        `json:"gcp_org_id,omitempty"`
	WorkspaceURL   string        `json:"workspace_url,omitempty"`
	MountRoot      string        `json:"mount_root,omitempty"`
}

type GuardrailConfig struct {
	Constitution    string `json:"constitution,omitempty"`
	AutoApproveMode bool   `json:"auto_approve_mode,omitempty"`
}

type Policy struct {
	Version       int               `json:"version"`
	OrgID         string            `json:"org_id"`
	UpdatedAt     time.Time         `json:"updated_at"`
	Network       []NetworkEndpoint `json:"network_whitelist"`
	DLPRules      []DLPRule         `json:"dlp_rules"`
	RBAC          RBACConfig        `json:"rbac"`
	AllowModels   []string          `json:"allow_models"`
	Features      map[string]bool   `json:"features"`
	VersionPolicy VersionPolicy     `json:"version_policy,omitempty"`
	OrgSettings   OrgSettings       `json:"org_settings,omitempty"`
	Guardrail     GuardrailConfig   `json:"guardrail,omitempty"`
	Signature     string            `json:"signature,omitempty"`
}

type VersionInfo struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

const MaxVersions = 10

type Store struct {
	mu  sync.RWMutex
	dir string
}

func NewStore(dir string) *Store {
	os.MkdirAll(dir, 0700)
	return &Store{dir: dir}
}

func DefaultPolicy(orgID string) *Policy {
	return &Policy{
		Version:   1,
		OrgID:     orgID,
		UpdatedAt: time.Now().UTC(),
		Network: []NetworkEndpoint{
			{Host: "api.anthropic.com", Ports: []int{443}, Methods: []string{"POST"}},
		},
		RBAC: RBACConfig{
			DefaultRole:   "user",
			EnforceStrict: true,
			Roles: []RBACRole{
				{Role: "owner", Permissions: []string{"policy:*", "org:*", "audit:*"}, SLevel: 4},
				{Role: "user", Permissions: []string{"workspace:use"}, SLevel: 2},
			},
		},
		AllowModels: []string{"claude-3-5-sonnet"},
		Features: map[string]bool{
			"scheduled_tasks": true,
			"remote_control":  false,
			"web_access":      false,
		},
		VersionPolicy: VersionPolicy{
			MinVersion:      "0.1.0",
			BlockedVersions: []string{},
			UpdateChannel:   "stable",
		},
		OrgSettings: OrgSettings{
			OrgName: orgID,
			AllowedSSO: []SSOProvider{
				{ID: "email_otp", Label: "Company Email OTP", Enabled: true, Configured: true},
			},
			MountRoot: "/workspace/boanclaw",
		},
		Guardrail: GuardrailConfig{
			Constitution: "가드레일 헌법: 자격증명, 비밀번호, 토큰, 개인정보, 사내 비밀, 고객 데이터, 민감한 운영 명령은 외부로 그대로 내보내지 않는다. 완전 무해한 일반 텍스트만 허용한다. 애매하면 ask 로 분류하고 사람 확인을 거친다.",
		},
	}
}

func (s *Store) orgDir(orgID string) string {
	d := filepath.Join(s.dir, orgID)
	os.MkdirAll(d, 0700)
	return d
}

func (s *Store) Save(p *Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.UpdatedAt = time.Now().UTC()
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.orgDir(p.OrgID), fmt.Sprintf("v%d.json", p.Version))
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return err
	}
	s.pruneVersions(p.OrgID)
	return nil
}

func (s *Store) Load(orgID string) (*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions := s.scanVersions(orgID)
	if len(versions) == 0 {
		return nil, fmt.Errorf("no policy for org %s", orgID)
	}
	return s.loadFile(s.orgDir(orgID), versions[len(versions)-1].Version)
}

func (s *Store) EnsureDefault(orgID string) (*Policy, error) {
	if p, err := s.Load(orgID); err == nil {
		return p, nil
	}
	p := DefaultPolicy(orgID)
	if err := s.Save(p); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Store) LoadVersion(orgID string, version int) (*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadFile(s.orgDir(orgID), version)
}

func (s *Store) ListVersions(orgID string) []VersionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scanVersions(orgID)
}

func (s *Store) NextVersion(orgID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions := s.scanVersions(orgID)
	if len(versions) == 0 {
		return 1
	}
	return versions[len(versions)-1].Version + 1
}

func (s *Store) scanVersions(orgID string) []VersionInfo {
	dir := s.orgDir(orgID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var versions []VersionInfo
	for _, e := range entries {
		var ver int
		if n, _ := fmt.Sscanf(e.Name(), "v%d.json", &ver); n == 1 {
			info, _ := e.Info()
			var updated time.Time
			if info != nil {
				updated = info.ModTime()
			}
			versions = append(versions, VersionInfo{Version: ver, UpdatedAt: updated})
		}
	}
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Version < versions[j].Version
	})
	return versions
}

func (s *Store) pruneVersions(orgID string) {
	versions := s.scanVersions(orgID)
	if len(versions) <= MaxVersions {
		return
	}
	dir := s.orgDir(orgID)
	for _, v := range versions[:len(versions)-MaxVersions] {
		os.Remove(filepath.Join(dir, fmt.Sprintf("v%d.json", v.Version)))
	}
}

func (s *Store) loadFile(dir string, version int) (*Policy, error) {
	path := filepath.Join(dir, fmt.Sprintf("v%d.json", version))
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.OrgSettings.MountRoot == "" {
		p.OrgSettings.MountRoot = "/workspace/boanclaw"
	}
	if p.Guardrail.Constitution == "" {
		p.Guardrail.Constitution = DefaultPolicy(p.OrgID).Guardrail.Constitution
	}
	return &p, nil
}
