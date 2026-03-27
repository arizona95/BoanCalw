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

type Policy struct {
	Version     int               `json:"version"`
	OrgID       string            `json:"org_id"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Network     []NetworkEndpoint `json:"network_whitelist"`
	DLPRules    []DLPRule         `json:"dlp_rules"`
	RBAC        RBACConfig        `json:"rbac"`
	AllowModels []string          `json:"allow_models"`
	Features    map[string]bool   `json:"features"`
	Signature   string            `json:"signature,omitempty"`
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
	return &p, json.Unmarshal(raw, &p)
}
