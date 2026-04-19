// Package killchain holds rules + incident history for automated endpoint
// response. A "rule" matches an incoming Wazuh/EDR alert (or manual trigger)
// against a process name / alert description pattern. When matched, the proxy
// runs a kill-chain sequence against the affected VM:
//
//  1. Network isolation — deny egress at firewall level.
//  2. RAM dump — winpmem on VM → upload to GCS.
//  3. Disk snapshot — GCP Custom Image of VM's boot disk.
//  4. Deallocate — VM STOP + DELETE.
//
// The incident record captures every step's status + artifact URIs so an
// investigator can download them later.
package killchain

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Rule — one detection pattern. Currently only process_name matching; future
// iterations may add wazuh rule ID, process signer, file path, etc.
type Rule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`                   // human label, e.g. "Block Claude CLI"
	ProcessName string `json:"process_name,omitempty"` // case-insensitive substring match. e.g. "claude"
	// Auto — true 면 Wazuh event 수신 시 즉시 kill chain 발동.
	// false 면 incident 만 기록하고 관리자가 수동으로 trigger.
	Auto        bool      `json:"auto"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// IncidentStep — single action within a kill chain.
type IncidentStep struct {
	Name       string    `json:"name"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Status     string    `json:"status"` // pending | running | success | failed | skipped
	Detail     string    `json:"detail,omitempty"`
	Artifact   string    `json:"artifact,omitempty"` // GCS URI / image URI etc.
}

// Incident — one kill chain execution.
type Incident struct {
	ID           string         `json:"id"`
	CreatedAt    time.Time      `json:"created_at"`
	Trigger      string         `json:"trigger"`     // "auto-wazuh" | "manual" | "test"
	RuleID       string         `json:"rule_id,omitempty"`
	RuleName     string         `json:"rule_name,omitempty"`
	TargetEmail  string         `json:"target_email"` // VM owner
	TargetVM     string         `json:"target_vm,omitempty"`
	MatchedEvent map[string]any `json:"matched_event,omitempty"`
	Steps        []IncidentStep `json:"steps"`
	Status       string         `json:"status"` // running | success | partial | failed
	Requester    string         `json:"requester,omitempty"`
}

const (
	maxIncidents = 500 // ring buffer
)

// Store — persists Rules + Incidents to a JSON file. Safe for concurrent use.
type Store struct {
	mu    sync.RWMutex
	path  string
	state state
}

type state struct {
	Rules     []Rule     `json:"rules"`
	Incidents []Incident `json:"incidents"`
}

func NewStore(dataDir string) (*Store, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("killchain: dataDir required")
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dataDir, err)
	}
	s := &Store{path: filepath.Join(dataDir, "killchain.json")}
	if err := s.load(); err != nil {
		return nil, err
	}
	// Seed default rule if empty — "block claude CLI".
	if len(s.state.Rules) == 0 {
		s.state.Rules = append(s.state.Rules, Rule{
			ID:          "rule-seed-claude",
			Name:        "Claude CLI on workstation",
			ProcessName: "claude",
			Auto:        false,
			Description: "Detects Anthropic Claude CLI running inside a managed Windows workstation. Disabled by default — admin must set auto=true to trigger kill chain automatically.",
			CreatedAt:   time.Now().UTC(),
		})
		_ = s.save()
	}
	return s, nil
}

func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, &s.state)
}

func (s *Store) save() error {
	raw, err := json.MarshalIndent(&s.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// ─── Rules ─────────────────────────────────────────────────────────────

func (s *Store) ListRules() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Rule, len(s.state.Rules))
	copy(out, s.state.Rules)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *Store) AddRule(r Rule) (Rule, error) {
	if r.Name == "" {
		return Rule{}, fmt.Errorf("rule.name required")
	}
	if r.ProcessName == "" {
		return Rule{}, fmt.Errorf("rule.process_name required (v1 은 프로세스명 매칭만 지원)")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.ID == "" {
		r.ID = fmt.Sprintf("rule-%d", time.Now().UnixNano())
	}
	r.CreatedAt = time.Now().UTC()
	s.state.Rules = append(s.state.Rules, r)
	if err := s.save(); err != nil {
		return Rule{}, err
	}
	return r, nil
}

func (s *Store) DeleteRule(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.state.Rules[:0]
	found := false
	for _, r := range s.state.Rules {
		if r.ID == id {
			found = true
			continue
		}
		out = append(out, r)
	}
	if !found {
		return fmt.Errorf("rule %s not found", id)
	}
	s.state.Rules = out
	return s.save()
}

func (s *Store) UpdateRuleAuto(id string, auto bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Rules {
		if s.state.Rules[i].ID == id {
			s.state.Rules[i].Auto = auto
			return s.save()
		}
	}
	return fmt.Errorf("rule %s not found", id)
}

// MatchProcess — returns first rule whose ProcessName is a case-insensitive
// substring of processName. nil if no match.
func (s *Store) MatchProcess(processName string) *Rule {
	if processName == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	target := lower(processName)
	for i := range s.state.Rules {
		r := &s.state.Rules[i]
		if r.ProcessName == "" {
			continue
		}
		if contains(target, lower(r.ProcessName)) {
			return r
		}
	}
	return nil
}

// ─── Incidents ─────────────────────────────────────────────────────────

func (s *Store) ListIncidents(limit int) []Incident {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 || limit > len(s.state.Incidents) {
		limit = len(s.state.Incidents)
	}
	out := make([]Incident, 0, limit)
	// newest first
	for i := len(s.state.Incidents) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, s.state.Incidents[i])
	}
	return out
}

func (s *Store) GetIncident(id string) (Incident, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, inc := range s.state.Incidents {
		if inc.ID == id {
			return inc, true
		}
	}
	return Incident{}, false
}

func (s *Store) CreateIncident(inc Incident) (Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if inc.ID == "" {
		inc.ID = fmt.Sprintf("inc-%d", time.Now().UnixNano())
	}
	inc.CreatedAt = time.Now().UTC()
	if inc.Status == "" {
		inc.Status = "running"
	}
	s.state.Incidents = append(s.state.Incidents, inc)
	if len(s.state.Incidents) > maxIncidents {
		s.state.Incidents = s.state.Incidents[len(s.state.Incidents)-maxIncidents:]
	}
	if err := s.save(); err != nil {
		return Incident{}, err
	}
	return inc, nil
}

// UpdateIncident — applies mutator under lock and persists.
func (s *Store) UpdateIncident(id string, mutator func(*Incident)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.Incidents {
		if s.state.Incidents[i].ID == id {
			mutator(&s.state.Incidents[i])
			return s.save()
		}
	}
	return fmt.Errorf("incident %s not found", id)
}

// AppendStep — atomic helper for runners to add a step + persist.
func (s *Store) AppendStep(incidentID string, step IncidentStep) error {
	return s.UpdateIncident(incidentID, func(inc *Incident) {
		inc.Steps = append(inc.Steps, step)
	})
}

// FinishStep — finds the last step with given name that is still running and
// marks it finished with the provided status/detail/artifact.
func (s *Store) FinishStep(incidentID, stepName, status, detail, artifact string) error {
	return s.UpdateIncident(incidentID, func(inc *Incident) {
		for i := len(inc.Steps) - 1; i >= 0; i-- {
			if inc.Steps[i].Name == stepName && inc.Steps[i].Status == "running" {
				inc.Steps[i].Status = status
				inc.Steps[i].Detail = detail
				inc.Steps[i].Artifact = artifact
				inc.Steps[i].FinishedAt = time.Now().UTC()
				return
			}
		}
	})
}

func lower(s string) string {
	// simple ASCII lowercase — sufficient for process names
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
