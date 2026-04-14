package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	// Path — 폴더 경로 (예: "/security/credentials"). 빈 문자열 or "/" = 루트.
	// 각 노드는 하나의 "skill" 을 나타내며, Path + Definition 으로 폴더 계층 구성.
	Path       string    `json:"path,omitempty"`
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
	// Reason — 왜 이 엣지가 생겼는지. inline_ref 의 경우 [[id|reason]] 의 reason.
	Reason string  `json:"reason,omitempty"`
	Weight float32 `json:"weight,omitempty"`
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
	now := time.Now().UTC()
	if n.CreatedAt.IsZero() {
		n.CreatedAt = now
	}
	n.UpdatedAt = now
	if n.ID == "" {
		n.ID = generateID("n")
	}
	if err := writeJSON(filepath.Join(s.orgDir(orgID), "nodes", n.ID+".json"), n); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()
	// inline link 동기화 (별도 lock 사용하므로 해제 후 호출).
	_, _, _ = s.SyncInlineLinks(orgID, n.ID, n.Content)
	return nil
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

func (s *WikiGraphStore) DeleteDialog(orgID, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.orgDir(orgID), "dialogs", id+".json")
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return nil
}

// ── Inline link 파싱 ────────────────────────────────────
//
// Notion 스타일 inline link:
//   [[node_id]]            — 단순 링크
//   [[node_id|링크 이유]]  — 이 링크가 왜 생겼는지 맥락
//
// 노드 저장 시 content 를 파싱해서 자동으로 edge(relation="inline_ref") 동기화.
// 이전 inline 링크 집합과 비교해 없어진 건 edge 삭제, 새로 생긴 건 edge 추가.

var inlineLinkRegex = regexp.MustCompile(`\[\[([a-zA-Z0-9_\-]+)(?:\|([^\]]*))?\]\]`)

type InlineLink struct {
	TargetID string
	Reason   string
}

// ParseInlineLinks — content 에서 [[id|reason]] 추출.
func ParseInlineLinks(content string) []InlineLink {
	matches := inlineLinkRegex.FindAllStringSubmatch(content, -1)
	out := make([]InlineLink, 0, len(matches))
	seen := make(map[string]bool) // 같은 target 중복은 첫 번째만 반영
	for _, m := range matches {
		target := m[1]
		if seen[target] {
			continue
		}
		seen[target] = true
		reason := ""
		if len(m) > 2 {
			reason = m[2]
		}
		out = append(out, InlineLink{TargetID: target, Reason: reason})
	}
	return out
}

// SyncInlineLinks — 노드 저장 후 호출: 이 노드의 inline_ref edge 를 content 와 동기화.
// 기존 inline_ref edge 중 content 에 없는 건 삭제, content 에 있는 새 것은 추가.
// 반환: (added, removed) 개수.
func (s *WikiGraphStore) SyncInlineLinks(orgID, nodeID, content string) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	parsed := ParseInlineLinks(content)
	parsedMap := make(map[string]string, len(parsed))
	for _, p := range parsed {
		parsedMap[p.TargetID] = p.Reason
	}

	// 기존 inline_ref edge 수집.
	allEdges, err := s.listEdgesLocked(orgID)
	if err != nil {
		return 0, 0, err
	}
	existingInline := make(map[string]*WikiEdge) // target -> edge
	for i := range allEdges {
		e := &allEdges[i]
		if e.From == nodeID && e.Relation == "inline_ref" {
			existingInline[e.To] = e
		}
	}

	added, removed := 0, 0
	// 없어진 것 삭제.
	for target, e := range existingInline {
		if _, stillThere := parsedMap[target]; !stillThere {
			_ = os.Remove(filepath.Join(s.orgDir(orgID), "edges", e.ID+".json"))
			removed++
		}
	}
	// 새로 생긴 것 추가 (reason 바뀐 경우도 업데이트).
	for target, reason := range parsedMap {
		// 대상 노드 존재 여부 확인 — 없으면 skip (dangling link 는 edge 안 만듦)
		if _, err := os.Stat(filepath.Join(s.orgDir(orgID), "nodes", target+".json")); err != nil {
			continue
		}
		if e, exists := existingInline[target]; exists {
			// reason 변경되면 업데이트
			if e.Relation == "inline_ref" {
				// weight 슬롯에 reason 해시를 넣진 않고, 간단히 edge 재저장.
				// 현재 WikiEdge 에 reason 필드 없음 — 별도 meta 로 확장 가능하지만
				// 일단 inline_ref 는 relation 으로만 식별, reason 은 content 원문에 있음.
				_ = e
			}
			continue
		}
		newEdge := WikiEdge{
			ID:       generateID("e"),
			From:     nodeID,
			To:       target,
			Relation: "inline_ref",
			Reason:   reason,
		}
		if err := writeJSON(filepath.Join(s.orgDir(orgID), "edges", newEdge.ID+".json"), &newEdge); err == nil {
			added++
		}
	}
	return added, removed, nil
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
