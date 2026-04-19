// Package endpointpolicy — 관리자가 배포한 PowerShell / shell 스크립트를 저장.
// 사용자 VM 안의 endpoint agent 가 주기적으로 GET 해서 가져가 실행한다.
//
// 데이터 모델:
//   - Policy: 이름 + 현재 script 본문 + 버전 (publish 할 때마다 +1)
//   - Run: policy 당 각 VM agent 의 마지막 실행 결과 (exit_code / stdout / stderr)
//
// 파일 레이아웃 (JSON, per-org):
//   {dataDir}/endpoint_policies/{org_id}.json
package endpointpolicy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type Policy struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Script    string    `json:"script"`
	Shell     string    `json:"shell"` // "powershell" | "cmd" (default powershell)
	Version   int       `json:"version"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Run struct {
	PolicyID string    `json:"policy_id"`
	Version  int       `json:"version"`
	AgentID  string    `json:"agent_id"` // VM instance name
	ExitCode int       `json:"exit_code"`
	Stdout   string    `json:"stdout"`
	Stderr   string    `json:"stderr"`
	At       time.Time `json:"at"`
}

type orgData struct {
	Policies []*Policy `json:"policies"`
	Runs     []*Run    `json:"runs"` // ring buffer — keep last 500 per org
}

type Store struct {
	mu      sync.RWMutex
	dataDir string
	orgs    map[string]*orgData // orgID → data
}

const maxRuns = 500

func New(dataDir string) (*Store, error) {
	s := &Store{dataDir: filepath.Join(dataDir, "endpoint_policies"), orgs: make(map[string]*orgData)}
	if err := os.MkdirAll(s.dataDir, 0700); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) path(orgID string) string {
	if orgID == "" {
		orgID = "default"
	}
	return filepath.Join(s.dataDir, orgID+".json")
}

func (s *Store) load(orgID string) *orgData {
	if d, ok := s.orgs[orgID]; ok {
		return d
	}
	d := &orgData{}
	b, err := os.ReadFile(s.path(orgID))
	if err == nil && len(b) > 0 {
		_ = json.Unmarshal(b, d)
	}
	s.orgs[orgID] = d
	return d
}

func (s *Store) save(orgID string) error {
	d := s.orgs[orgID]
	if d == nil {
		return nil
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path(orgID), b, 0600)
}

// List — 특정 org 의 모든 정책 (최신순).
func (s *Store) List(orgID string) []*Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d := s.load(orgID)
	out := make([]*Policy, len(d.Policies))
	copy(out, d.Policies)
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out
}

// Get — id 로 정책 조회.
func (s *Store) Get(orgID, id string) *Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d := s.load(orgID)
	for _, p := range d.Policies {
		if p.ID == id {
			c := *p
			return &c
		}
	}
	return nil
}

// Upsert — id 가 있으면 script/enabled 업데이트 (버전 bump), 없으면 새 policy.
func (s *Store) Upsert(orgID string, p *Policy) (*Policy, error) {
	if p == nil || p.Name == "" || p.Script == "" {
		return nil, fmt.Errorf("name and script required")
	}
	if p.Shell == "" {
		p.Shell = "powershell"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load(orgID)
	now := time.Now().UTC()
	if p.ID == "" {
		// new
		p.ID = fmt.Sprintf("ep-%d", now.UnixNano())
		p.Version = 1
		p.CreatedAt = now
		p.UpdatedAt = now
		p.Enabled = true
		d.Policies = append(d.Policies, p)
		if err := s.save(orgID); err != nil {
			return nil, err
		}
		return p, nil
	}
	// update existing
	for i, existing := range d.Policies {
		if existing.ID == p.ID {
			// 버전 bump 조건: script 나 name 이 바뀐 경우
			if existing.Script != p.Script || existing.Name != p.Name || existing.Shell != p.Shell {
				p.Version = existing.Version + 1
			} else {
				p.Version = existing.Version
			}
			p.CreatedAt = existing.CreatedAt
			p.UpdatedAt = now
			d.Policies[i] = p
			if err := s.save(orgID); err != nil {
				return nil, err
			}
			return p, nil
		}
	}
	return nil, fmt.Errorf("policy %s not found", p.ID)
}

// Delete — id 의 정책 제거.
func (s *Store) Delete(orgID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load(orgID)
	for i, p := range d.Policies {
		if p.ID == id {
			d.Policies = append(d.Policies[:i], d.Policies[i+1:]...)
			return s.save(orgID)
		}
	}
	return nil
}

// NextForAgent — agent 가 마지막으로 실행한 버전을 기준으로, 아직 실행 안 한
// enabled 정책 중 첫 번째를 반환. 없으면 nil.
func (s *Store) NextForAgent(orgID, agentID string, lastRunVersions map[string]int) *Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d := s.load(orgID)
	// policy 순회 — 업데이트가 오래된 순 (안정적 순서)
	pols := make([]*Policy, len(d.Policies))
	copy(pols, d.Policies)
	sort.Slice(pols, func(i, j int) bool { return pols[i].UpdatedAt.Before(pols[j].UpdatedAt) })
	for _, p := range pols {
		if !p.Enabled {
			continue
		}
		last := lastRunVersions[p.ID]
		if last >= p.Version {
			continue // agent 가 이미 이 버전 실행함
		}
		// 실제로 agent 가 이 policy 에 대해 "어떤 version" 까지 돌렸는지는
		// runs 로그에서도 확인 (client 가 lastRunVersions 를 잃어버리는 경우).
		latestRun := 0
		for _, r := range d.Runs {
			if r.AgentID == agentID && r.PolicyID == p.ID && r.Version > latestRun {
				latestRun = r.Version
			}
		}
		if latestRun >= p.Version {
			continue
		}
		c := *p
		return &c
	}
	return nil
}

// RecordRun — agent 가 보낸 실행 결과 저장. ring buffer 로 관리.
func (s *Store) RecordRun(orgID string, r *Run) error {
	if r == nil || r.AgentID == "" || r.PolicyID == "" {
		return fmt.Errorf("agent_id and policy_id required")
	}
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.load(orgID)
	d.Runs = append(d.Runs, r)
	if len(d.Runs) > maxRuns {
		d.Runs = d.Runs[len(d.Runs)-maxRuns:]
	}
	return s.save(orgID)
}

// Runs — 최근 run 들 반환 (최신순). limit=0 이면 전체.
func (s *Store) Runs(orgID string, policyID string, limit int) []*Run {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d := s.load(orgID)
	out := make([]*Run, 0, len(d.Runs))
	for i := len(d.Runs) - 1; i >= 0; i-- {
		r := d.Runs[i]
		if policyID != "" && r.PolicyID != policyID {
			continue
		}
		out = append(out, r)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}
