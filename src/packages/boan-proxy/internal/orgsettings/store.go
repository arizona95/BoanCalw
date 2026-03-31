package orgsettings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type OrgRecord struct {
	OrgID       string                 `json:"org_id"`
	DisplayName string                 `json:"display_name,omitempty"`
	Settings    map[string]interface{} `json:"settings"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

type persisted struct {
	Orgs map[string]*OrgRecord `json:"orgs"`
}

type Store struct {
	mu      sync.RWMutex
	orgs    map[string]*OrgRecord
	dataDir string
}

func New(dataDir string) (*Store, error) {
	s := &Store{orgs: make(map[string]*OrgRecord), dataDir: dataDir}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	_ = s.load()
	return s, nil
}

func (s *Store) GetOrCreate(orgID string) *OrgRecord {
	if orgID == "" {
		orgID = "default"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.orgs[orgID]; ok {
		return r
	}
	r := &OrgRecord{
		OrgID:     orgID,
		Settings:  map[string]interface{}{},
		UpdatedAt: time.Now().UTC(),
	}
	s.orgs[orgID] = r
	_ = s.save()
	return r
}

func (s *Store) Patch(orgID string, displayName *string, settings map[string]interface{}) (*OrgRecord, error) {
	if orgID == "" {
		orgID = "default"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.orgs[orgID]
	if !ok {
		r = &OrgRecord{OrgID: orgID, Settings: map[string]interface{}{}}
		s.orgs[orgID] = r
	}
	if displayName != nil {
		r.DisplayName = *displayName
	}
	if settings != nil {
		if r.Settings == nil {
			r.Settings = map[string]interface{}{}
		}
		for k, v := range settings {
			r.Settings[k] = v
		}
	}
	r.UpdatedAt = time.Now().UTC()
	if err := s.save(); err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) path() string {
	return filepath.Join(s.dataDir, "org_settings.json")
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path())
	if err != nil {
		return err
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	if p.Orgs == nil {
		return nil
	}
	s.orgs = p.Orgs
	return nil
}

func (s *Store) save() error {
	p := persisted{Orgs: s.orgs}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path(), b, 0600)
}
