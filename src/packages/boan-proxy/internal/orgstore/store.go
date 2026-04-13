// Package orgstore manages the list of organization endpoints this proxy
// knows about. Each entry is {org_id, url, token, label}. The store is persisted
// to a JSON file and consulted at request time to route to the correct
// policy-server.
//
// Motivation: one host may participate in multiple organizations. The login
// screen lets the user pick which org to authenticate against; every admin API
// call picks the right (url, token) pair from here.
package orgstore

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/orgserver"
)

type Entry struct {
	OrgID string `json:"org_id"`
	URL   string `json:"url"`
	Token string `json:"token"`
	Label string `json:"label,omitempty"`
}

type snapshot struct {
	ActiveOrgID string  `json:"active_org_id,omitempty"`
	Orgs        []Entry `json:"orgs"`
}

type Store struct {
	mu     sync.RWMutex
	path   string
	active string
	orgs   map[string]Entry
}

var (
	ErrNotFound = errors.New("org not found")
	ErrExists   = errors.New("org already exists")
	ErrBadInput = errors.New("invalid input: org_id, url, token required")
)

// New loads the store from path. Missing file → empty store.
// If seed is non-nil and the store is empty on disk, the seed entry is added
// and marked active (typical case: first startup with legacy env vars).
func New(path string, seed *Entry) (*Store, error) {
	s := &Store{path: path, orgs: map[string]Entry{}}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if len(s.orgs) == 0 && seed != nil && seed.OrgID != "" && seed.URL != "" {
		s.orgs[seed.OrgID] = *seed
		s.active = seed.OrgID
		if err := s.save(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var snap snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return err
	}
	for _, e := range snap.Orgs {
		s.orgs[e.OrgID] = e
	}
	s.active = snap.ActiveOrgID
	if s.active == "" && len(snap.Orgs) > 0 {
		s.active = snap.Orgs[0].OrgID
	}
	return nil
}

func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	out := snapshot{ActiveOrgID: s.active, Orgs: make([]Entry, 0, len(s.orgs))}
	for _, e := range s.orgs {
		out.Orgs = append(out.Orgs, e)
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, raw, 0600)
}

// List returns all known orgs. Sensitive token is included; callers that
// expose this over HTTP must redact per role.
func (s *Store) List() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0, len(s.orgs))
	for _, e := range s.orgs {
		out = append(out, e)
	}
	return out
}

// PublicList returns entries with the token redacted — safe for unauthenticated
// callers (e.g., the login screen's org picker).
func (s *Store) PublicList() []Entry {
	raw := s.List()
	out := make([]Entry, len(raw))
	for i, e := range raw {
		e.Token = ""
		out[i] = e
	}
	return out
}

// Active returns the currently-active org entry. Used when no explicit
// org_id is supplied (backward compat with single-org paths).
func (s *Store) Active() (Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active == "" {
		return Entry{}, false
	}
	e, ok := s.orgs[s.active]
	return e, ok
}

func (s *Store) ActiveID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.active
}

func (s *Store) SetActive(orgID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	orgID = strings.TrimSpace(orgID)
	if _, ok := s.orgs[orgID]; !ok {
		return ErrNotFound
	}
	s.active = orgID
	return s.save()
}

func (s *Store) Get(orgID string) (Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.orgs[orgID]
	return e, ok
}

// Resolve picks the right entry: the one named orgID, else the active one.
// Returns zero-value Entry if neither exists.
func (s *Store) Resolve(orgID string) (Entry, bool) {
	orgID = strings.TrimSpace(orgID)
	if orgID != "" {
		if e, ok := s.Get(orgID); ok {
			return e, true
		}
	}
	return s.Active()
}

func (s *Store) Add(e Entry) error {
	e.OrgID = strings.TrimSpace(e.OrgID)
	e.URL = strings.TrimRight(strings.TrimSpace(e.URL), "/")
	e.Token = strings.TrimSpace(e.Token)
	if e.OrgID == "" || e.URL == "" || e.Token == "" {
		return ErrBadInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[e.OrgID]; ok {
		return ErrExists
	}
	s.orgs[e.OrgID] = e
	if s.active == "" {
		s.active = e.OrgID
	}
	return s.save()
}

func (s *Store) Upsert(e Entry) error {
	e.OrgID = strings.TrimSpace(e.OrgID)
	e.URL = strings.TrimRight(strings.TrimSpace(e.URL), "/")
	e.Token = strings.TrimSpace(e.Token)
	if e.OrgID == "" || e.URL == "" || e.Token == "" {
		return ErrBadInput
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orgs[e.OrgID] = e
	if s.active == "" {
		s.active = e.OrgID
	}
	return s.save()
}

func (s *Store) Remove(orgID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[orgID]; !ok {
		return ErrNotFound
	}
	delete(s.orgs, orgID)
	if s.active == orgID {
		s.active = ""
		for id := range s.orgs {
			s.active = id
			break
		}
	}
	return s.save()
}

// ClientFor returns an orgserver.Client configured for the given org.
// Falls back to the active org if orgID is empty/unknown.
// Returns a disabled client (empty baseURL) if no orgs are configured at all.
func (s *Store) ClientFor(orgID string) *orgserver.Client {
	entry, ok := s.Resolve(orgID)
	if !ok {
		return orgserver.New("")
	}
	return orgserver.NewWithToken(entry.URL, entry.Token)
}
