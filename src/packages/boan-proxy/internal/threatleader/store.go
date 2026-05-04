package threatleader

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store — Threat Leader 의 영구 상태. JSON 파일 1개에 seen/ignored/latest/lastFetch 보존.
type Store struct {
	mu    sync.RWMutex
	path  string
	state State
}

func NewStore(dataDir string) (*Store, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("threatleader: dataDir required")
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dataDir, err)
	}
	s := &Store{
		path: filepath.Join(dataDir, "threat-leader.json"),
		state: State{
			Seen:    map[string]bool{},
			Ignored: map[string]bool{},
			Latest:  []Proposal{},
		},
	}
	if err := s.load(); err != nil {
		return nil, err
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
	var st State
	if jerr := json.Unmarshal(raw, &st); jerr != nil {
		return fmt.Errorf("threat-leader load: %w", jerr)
	}
	if st.Seen == nil {
		st.Seen = map[string]bool{}
	}
	if st.Ignored == nil {
		st.Ignored = map[string]bool{}
	}
	if st.Latest == nil {
		st.Latest = []Proposal{}
	}
	s.state = st
	return nil
}

func (s *Store) save() error {
	raw, err := json.MarshalIndent(&s.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, raw, 0o600)
}

// Snapshot — 현재 state 의 thread-safe 복사본 반환 (UI GET).
func (s *Store) Snapshot() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := State{
		Seen:        cloneBoolSet(s.state.Seen),
		Ignored:     cloneBoolSet(s.state.Ignored),
		LastFetchAt: s.state.LastFetchAt,
		Latest:      append([]Proposal{}, s.state.Latest...),
	}
	return out
}

func cloneBoolSet(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// SetLatest — refresher 가 OSV fetch 후 호출. timestamp 갱신.
func (s *Store) SetLatest(ps []Proposal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Latest = ps
	s.state.LastFetchAt = time.Now().UTC()
	return s.save()
}

// MarkSeen — Accept 시. KillChain rule 등록 후 호출.
func (s *Store) MarkSeen(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Seen[id] = true
	// latest 에서 즉시 제거 (UI 새로고침 없이 사라지게).
	s.state.Latest = removeProposal(s.state.Latest, id)
	return s.save()
}

// MarkIgnored — Reject 시. 다음 라운드에 후보에서 제외.
func (s *Store) MarkIgnored(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Ignored[id] = true
	s.state.Latest = removeProposal(s.state.Latest, id)
	return s.save()
}

// FindProposal — UI 가 Accept/Reject 시 ID 로 advisory detail 가져옴.
func (s *Store) FindProposal(id string) (*Proposal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.state.Latest {
		if s.state.Latest[i].ID == id {
			p := s.state.Latest[i]
			return &p, true
		}
	}
	return nil, false
}

func removeProposal(list []Proposal, id string) []Proposal {
	out := list[:0]
	for _, p := range list {
		if p.ID != id {
			out = append(out, p)
		}
	}
	return out
}
