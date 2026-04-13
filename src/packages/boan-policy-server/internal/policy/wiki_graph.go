package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ── Wiki 그래프 모델 ────────────────────────────────────────────────
//
// 컨셉:
//   "LLM 이 자기 자신의 메모리공간을 수정한다" — Wiki 는 노드+엣지 그래프.
//   "LLM 이 자기 행동결정에 의문을 갖는다" — 애매한 노드를 find_ambiguous 가 발견.
//   "LLM 이 예시를 들어 사용자에게 물어본다" — ClarificationDialog 로 기록.
//
// 데이터 3종:
//   1) DecisionLog            — approve/deny 라벨 (HITL training log)
//   2) ClarificationDialog    — LLM↔인간 심층 대화
//   3) Wiki(Nodes+Edges)      — LLM 의 이전 생각 누적

// WikiNode — 생각의 노드.
//   Definition ≤ 30자 (핵심 한 줄 정의)
//   Content    ≤ 1000자 (실제 생각 본문)
type WikiNode struct {
	ID         string    `json:"id"`
	Definition string    `json:"definition"`
	Content    string    `json:"content"`
	Tags       []string  `json:"tags,omitempty"`
	CreatedBy  string    `json:"created_by,omitempty"` // skill 이름 또는 "human"
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// WikiEdge — 방향 엣지.
//   Relation:
//     "supports"      — From 이 To 를 뒷받침
//     "contradicts"   — From 이 To 와 모순
//     "refines"       — From 이 To 를 더 정교하게
//     "example_of"    — From 은 To 의 구체 예시
//     "depends_on"    — From 은 To 가 전제되어야 성립
//     "evolved_from"  — From 은 To 로부터 발전한 생각
type WikiEdge struct {
	ID       string  `json:"id"`
	From     string  `json:"from"`
	To       string  `json:"to"`
	Relation string  `json:"relation"`
	Weight   float32 `json:"weight,omitempty"`
}

// DecisionLog — approve/deny 라벨.
type DecisionLog struct {
	ID        string    `json:"id"`
	Input     string    `json:"input"`
	Decision  string    `json:"decision"` // "approve" | "deny"
	Reason    string    `json:"reason,omitempty"`
	Labeler   string    `json:"labeler,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// ClarificationDialog — LLM 이 애매한 부분을 물어본 대화 세션.
type ClarificationDialog struct {
	ID          string           `json:"id"`
	TopicNodeID string           `json:"topic_node_id,omitempty"`
	Turns       []DialogTurn     `json:"turns"`
	StartedAt   time.Time        `json:"started_at"`
	EndedAt     *time.Time       `json:"ended_at,omitempty"`
}

type DialogTurn struct {
	Role     string   `json:"role"` // "llm" | "human"
	Content  string   `json:"content"`
	Examples []string `json:"examples,omitempty"` // LLM 이 든 애매한 예시
}

// ── 검증 한계 ──────────────────────────────────────────────
const (
	MaxDefinitionLen = 30
	MaxContentLen    = 1000
)

var (
	ErrWikiNodeNotFound = errors.New("wiki node not found")
	ErrWikiEdgeNotFound = errors.New("wiki edge not found")
	ErrDefTooLong       = fmt.Errorf("definition exceeds %d chars", MaxDefinitionLen)
	ErrContentTooLong   = fmt.Errorf("content exceeds %d chars", MaxContentLen)
)

// ── Store ─────────────────────────────────────────────────

type WikiGraphStore struct {
	mu   sync.RWMutex
	base string
}

func NewWikiGraphStore(base string) *WikiGraphStore {
	return &WikiGraphStore{base: base}
}

func (s *WikiGraphStore) orgDir(orgID string) string {
	d := filepath.Join(s.base, orgID, "wiki_graph")
	_ = os.MkdirAll(filepath.Join(d, "nodes"), 0700)
	_ = os.MkdirAll(filepath.Join(d, "edges"), 0700)
	_ = os.MkdirAll(filepath.Join(d, "decisions"), 0700)
	_ = os.MkdirAll(filepath.Join(d, "dialogs"), 0700)
	return d
}

// ── Node CRUD ─────────────────────────────────────────────

func (s *WikiGraphStore) UpsertNode(orgID string, n *WikiNode) error {
	if len([]rune(n.Definition)) > MaxDefinitionLen {
		return ErrDefTooLong
	}
	if len([]rune(n.Content)) > MaxContentLen {
		return ErrContentTooLong
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if n.CreatedAt.IsZero() {
		n.CreatedAt = now
	}
	n.UpdatedAt = now
	if n.ID == "" {
		n.ID = generateID("n")
	}
	return writeJSON(filepath.Join(s.orgDir(orgID), "nodes", n.ID+".json"), n)
}

func (s *WikiGraphStore) GetNode(orgID, id string) (*WikiNode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var n WikiNode
	if err := readJSON(filepath.Join(s.orgDir(orgID), "nodes", id+".json"), &n); err != nil {
		if os.IsNotExist(err) {
			return nil, ErrWikiNodeNotFound
		}
		return nil, err
	}
	return &n, nil
}

func (s *WikiGraphStore) DeleteNode(orgID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// 노드 삭제 시 연결된 엣지도 정리.
	edges, _ := s.listEdgesLocked(orgID)
	for _, e := range edges {
		if e.From == id || e.To == id {
			_ = os.Remove(filepath.Join(s.orgDir(orgID), "edges", e.ID+".json"))
		}
	}
	if err := os.Remove(filepath.Join(s.orgDir(orgID), "nodes", id+".json")); err != nil {
		if os.IsNotExist(err) {
			return ErrWikiNodeNotFound
		}
		return err
	}
	return nil
}

func (s *WikiGraphStore) ListNodes(orgID string) ([]WikiNode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries, err := os.ReadDir(filepath.Join(s.orgDir(orgID), "nodes"))
	if err != nil {
		return nil, err
	}
	out := make([]WikiNode, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var n WikiNode
		if err := readJSON(filepath.Join(s.orgDir(orgID), "nodes", e.Name()), &n); err == nil {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out, nil
}

// ── Edge CRUD ─────────────────────────────────────────────

func (s *WikiGraphStore) UpsertEdge(orgID string, e *WikiEdge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.ID == "" {
		e.ID = generateID("e")
	}
	return writeJSON(filepath.Join(s.orgDir(orgID), "edges", e.ID+".json"), e)
}

func (s *WikiGraphStore) DeleteEdge(orgID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Remove(filepath.Join(s.orgDir(orgID), "edges", id+".json")); err != nil {
		if os.IsNotExist(err) {
			return ErrWikiEdgeNotFound
		}
		return err
	}
	return nil
}

func (s *WikiGraphStore) ListEdges(orgID string) ([]WikiEdge, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listEdgesLocked(orgID)
}

func (s *WikiGraphStore) listEdgesLocked(orgID string) ([]WikiEdge, error) {
	entries, err := os.ReadDir(filepath.Join(s.orgDir(orgID), "edges"))
	if err != nil {
		return nil, err
	}
	out := make([]WikiEdge, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var we WikiEdge
		if err := readJSON(filepath.Join(s.orgDir(orgID), "edges", e.Name()), &we); err == nil {
			out = append(out, we)
		}
	}
	return out, nil
}

// ── DecisionLog (approve/deny 누적) ──────────────────────

func (s *WikiGraphStore) AppendDecision(orgID string, d *DecisionLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.ID == "" {
		d.ID = generateID("d")
	}
	if d.Timestamp.IsZero() {
		d.Timestamp = time.Now().UTC()
	}
	return writeJSON(filepath.Join(s.orgDir(orgID), "decisions", d.ID+".json"), d)
}

func (s *WikiGraphStore) ListDecisions(orgID string, limit int) ([]DecisionLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries, err := os.ReadDir(filepath.Join(s.orgDir(orgID), "decisions"))
	if err != nil {
		return nil, err
	}
	out := make([]DecisionLog, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var d DecisionLog
		if err := readJSON(filepath.Join(s.orgDir(orgID), "decisions", e.Name()), &d); err == nil {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp.After(out[j].Timestamp) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ── ClarificationDialog (LLM↔Human 심층 대화) ────────────

func (s *WikiGraphStore) UpsertDialog(orgID string, d *ClarificationDialog) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.ID == "" {
		d.ID = generateID("dlg")
	}
	if d.StartedAt.IsZero() {
		d.StartedAt = time.Now().UTC()
	}
	return writeJSON(filepath.Join(s.orgDir(orgID), "dialogs", d.ID+".json"), d)
}

func (s *WikiGraphStore) ListDialogs(orgID string, limit int) ([]ClarificationDialog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries, err := os.ReadDir(filepath.Join(s.orgDir(orgID), "dialogs"))
	if err != nil {
		return nil, err
	}
	out := make([]ClarificationDialog, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var d ClarificationDialog
		if err := readJSON(filepath.Join(s.orgDir(orgID), "dialogs", e.Name()), &d); err == nil {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ── Helpers ──────────────────────────────────────────────

func generateID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}
