// Package wikiskills — Layer B skills 실행 엔진.
//
// 컨셉:
//   LLM 이 자기 자신의 메모리공간(Wiki 그래프)을 수정한다.
//   LLM 이 자기 결정에 의문을 갖는다.
//   LLM 이 애매한 부분을 예시 들어 사용자에게 묻는다.
//
// 설계:
//   각 skill 은 "system prompt + JSON 응답 스키마" 로 LLM 호출.
//   LLM 은 primitive graph actions (create_node, create_edge, 등) 의 시퀀스를
//   JSON 으로 반환. 본 엔진이 그 actions 를 실제 graph HTTP API 로 디스패치.
//
// 사용하는 LLM 은 전부 LLM Registry 를 경유해서 찾음 (role="g3" 또는 "wiki_edit").
package wikiskills

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// GraphClient — policy-server 의 wiki-graph primitive API 에 접근.
type GraphClient struct {
	BaseURL  string
	OrgID    string
	OrgToken string
	HTTP     *http.Client
}

func NewGraphClient(baseURL, orgID, orgToken string) *GraphClient {
	return &GraphClient{
		BaseURL:  strings.TrimRight(baseURL, "/"),
		OrgID:    orgID,
		OrgToken: orgToken,
		HTTP: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{Proxy: nil}, // NO proxy — 내부 호출
		},
	}
}

func (c *GraphClient) call(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(raw)
	}
	url := fmt.Sprintf("%s/org/%s/v1/wiki-graph/%s", c.BaseURL, c.OrgID, path)
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.OrgToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.OrgToken)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("graph %s %s: %d %s", method, path, resp.StatusCode, string(b))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// ── Graph model (policy-server 와 동일한 shape) ──────────

type Node struct {
	ID         string    `json:"id,omitempty"`
	Path       string    `json:"path,omitempty"` // 폴더 경로 ("/security/credentials" 식)
	Definition string    `json:"definition"`
	Content    string    `json:"content"`
	Tags       []string  `json:"tags,omitempty"`
	CreatedBy  string    `json:"created_by,omitempty"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
}

type Edge struct {
	ID       string  `json:"id,omitempty"`
	From     string  `json:"from"`
	To       string  `json:"to"`
	Relation string  `json:"relation"`
	Reason   string  `json:"reason,omitempty"`
	Weight   float32 `json:"weight,omitempty"`
}

type Decision struct {
	ID       string `json:"id,omitempty"`
	Input    string `json:"input"`
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
	Labeler  string `json:"labeler,omitempty"`
}

func (c *GraphClient) ListNodes(ctx context.Context) ([]Node, error) {
	var ns []Node
	err := c.call(ctx, "GET", "nodes", nil, &ns)
	return ns, err
}
func (c *GraphClient) ListEdges(ctx context.Context) ([]Edge, error) {
	var es []Edge
	err := c.call(ctx, "GET", "edges", nil, &es)
	return es, err
}
func (c *GraphClient) CreateNode(ctx context.Context, n Node) (*Node, error) {
	var out Node
	err := c.call(ctx, "POST", "nodes", n, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}
func (c *GraphClient) UpdateNode(ctx context.Context, id string, patch map[string]any) (*Node, error) {
	var out Node
	err := c.call(ctx, "PATCH", "nodes/"+id, patch, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}
func (c *GraphClient) CreateEdge(ctx context.Context, e Edge) (*Edge, error) {
	var out Edge
	err := c.call(ctx, "POST", "edges", e, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}
func (c *GraphClient) AppendDecision(ctx context.Context, d Decision) error {
	return c.call(ctx, "POST", "decisions", d, nil)
}

// UpdateDecisionLabel — HITL label-fix 승인 시 사용. id 로 찾아서 decision 필드
// (approve/deny) 만 바꿈. 반환: 수정 후 Decision.
func (c *GraphClient) UpdateDecisionLabel(ctx context.Context, id, newLabel, reason string) (*Decision, error) {
	var out Decision
	body := map[string]any{"decision": newLabel, "reason": reason}
	err := c.call(ctx, "PATCH", "decisions/"+id, body, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}
func (c *GraphClient) DeleteNode(ctx context.Context, id string) error {
	return c.call(ctx, "DELETE", "nodes/"+id, nil, nil)
}
func (c *GraphClient) ListDialogsRaw(ctx context.Context, limit int) ([]ClarificationDialog, error) {
	var ds []ClarificationDialog
	err := c.call(ctx, "GET", fmt.Sprintf("dialogs?limit=%d", limit), nil, &ds)
	return ds, err
}

// ── Dialog model ────────────────────────────────────────
type DialogTurn struct {
	Role     string   `json:"role"` // "llm" | "human"
	Content  string   `json:"content"`
	Examples []string `json:"examples,omitempty"`
}
type ClarificationDialog struct {
	ID          string       `json:"id,omitempty"`
	TopicNodeID string       `json:"topic_node_id,omitempty"`
	Turns       []DialogTurn `json:"turns"`
}

func (c *GraphClient) ListDecisions(ctx context.Context, limit int) ([]Decision, error) {
	var ds []Decision
	err := c.call(ctx, "GET", fmt.Sprintf("decisions?limit=%d", limit), nil, &ds)
	return ds, err
}
func (c *GraphClient) UpsertDialog(ctx context.Context, d ClarificationDialog) (*ClarificationDialog, error) {
	var out ClarificationDialog
	err := c.call(ctx, "POST", "dialogs", d, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *GraphClient) DeleteDialog(ctx context.Context, id string) error {
	return c.call(ctx, "DELETE", "dialogs/"+id, nil, nil)
}

// ── LLM 호출 ─────────────────────────────────────────────

type LLMConfig struct {
	URL   string // OpenAI 호환 /v1/chat/completions
	Model string
	Key   string
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float32       `json:"temperature"`
	Stream      bool          `json:"stream"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
	// ollama 호환 필드 — thinking tokens 억제.
	Think   bool `json:"think"`
	Options struct {
		NumPredict  int     `json:"num_predict,omitempty"`
		Temperature float32 `json:"temperature,omitempty"`
	} `json:"options,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	// Ollama plain /api/generate fallback
	Message  struct{ Content string `json:"content"` } `json:"message"`
	Response string                                    `json:"response"`
}

func callLLM(ctx context.Context, cfg LLMConfig, system, user string) (string, error) {
	if cfg.URL == "" || cfg.Model == "" {
		return "", fmt.Errorf("llm not configured (url/model empty)")
	}
	reqBody := chatRequest{
		Model: cfg.Model,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Temperature: 0.2,
		Stream:      false,
		MaxTokens:   2048,
		Think:       false,
	}
	reqBody.Options.NumPredict = 2048
	reqBody.Options.Temperature = 0.2
	raw, _ := json.Marshal(reqBody)
	// HTTP_PROXY 무시.
	httpClient := &http.Client{Timeout: 600 * time.Second, Transport: &http.Transport{Proxy: nil}}
	req, _ := http.NewRequestWithContext(ctx, "POST", cfg.URL, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if cfg.Key != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Key)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", fmt.Errorf("llm returned %d: %s", resp.StatusCode, string(b))
	}
	var parsed chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", err
	}
	if len(parsed.Choices) > 0 {
		return parsed.Choices[0].Message.Content, nil
	}
	if parsed.Message.Content != "" {
		return parsed.Message.Content, nil
	}
	return parsed.Response, nil
}

// ── skill.wiki_edit ──────────────────────────────────────
//
// 입력: DecisionLog 1건
// 과정:
//   1) graph 현재 상태 요약 (기존 노드 리스트)
//   2) LLM 에 system prompt + decision 전달
//   3) LLM 이 JSON 으로 actions 반환:
//        [{type: create_node, definition, content, tags},
//         {type: update_node, id, content_append},
//         {type: create_edge, from, to, relation, reason}]
//   4) 본 엔진이 actions 를 graph API 호출로 실행
//
// 방금 만든 노드의 ID 는 결과에 담기므로 LLM 의 다음 turn(이 있다면) 에서 참조 가능.
// 본 버전은 1-turn (action 한 batch). 이후 multi-turn 확장.

type Action struct {
	Type string `json:"type"`
	// create_node
	Definition string   `json:"definition,omitempty"`
	Content    string   `json:"content,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	// update_node / create_edge
	NodeID string `json:"node_id,omitempty"`
	// create_edge
	From     string  `json:"from,omitempty"`
	To       string  `json:"to,omitempty"`
	Relation string  `json:"relation,omitempty"`
	Reason   string  `json:"reason,omitempty"`
	Weight   float32 `json:"weight,omitempty"`
	// update_node
	ContentAppend string `json:"content_append,omitempty"`
	// meta
	ReasonText string `json:"reason_text,omitempty"` // 왜 이 액션인지 LLM 의 설명
}

type SkillResult struct {
	ActionsPlanned  int      `json:"actions_planned"`
	NodesCreated    []string `json:"nodes_created"`
	NodesUpdated    []string `json:"nodes_updated"`
	EdgesCreated    []string `json:"edges_created"`
	Errors          []string `json:"errors,omitempty"`
	LLMRaw          string   `json:"llm_raw,omitempty"`
}

const systemPromptWikiEdit = `You manage a knowledge graph that encodes guardrail lessons from HITL (human-in-the-loop) approve/deny decisions. Your job is to update the graph to reflect a new decision.

GRAPH MODEL
- Node: {definition (<=30 chars, korean ok), content (<=1000 chars), tags}
- Edge: {from, to, relation, reason}; relations: supports, contradicts, refines, example_of, depends_on, evolved_from, inline_ref

PRINCIPLES
- One node = one thought. If a thought grows beyond ~1000 chars or spans multiple concepts, split into separate nodes and link with edges.
- Prefer UPDATE over CREATE when an existing node covers the same pattern. Append a short example (one line) to the content.
- Create edges to encode "A supports B", "A is an example of B", "A contradicts B" when the relationship is clear.
- You MAY embed inline links in content with [[node_id|why]] syntax — they auto-generate inline_ref edges.

INPUT
You'll receive a decision (input text + approve/deny + reason) and the current list of nodes.

OUTPUT — strict JSON only, no prose:
{
  "actions": [
    {"type": "create_node", "definition": "<30자 정의>", "content": "<내용>", "tags": ["tag1"], "reason_text": "왜 이 노드"},
    {"type": "update_node", "node_id": "n_xxx", "content_append": "- 추가 예시 한줄", "reason_text": "기존 노드에 예시 추가"},
    {"type": "create_edge", "from": "n_a", "to": "n_b", "relation": "supports", "reason": "관계 이유", "reason_text": "왜 이 엣지"}
  ]
}

RULES
- Return ONLY valid JSON. No markdown fences, no commentary.
- If decision is "approve" (benign data), usually no actions needed — return {"actions": []}.
- If decision is "deny" (risky data), at minimum either update an existing node or create a new one.
- Limit to max 5 actions per call.
- Do not reference node ids that do not exist in the current list (except ones you just created in this batch — but this is single-batch, so don't).`

func summarizeNodes(nodes []Node) string {
	if len(nodes) == 0 {
		return "(no nodes yet — graph is empty)"
	}
	var sb strings.Builder
	for _, n := range nodes {
		tags := strings.Join(n.Tags, ",")
		sb.WriteString(fmt.Sprintf("- [%s] %s [%s]\n", n.ID, n.Definition, tags))
	}
	return sb.String()
}

// RunWikiEdit — 한 decision 에 대해 LLM skill 실행.
func RunWikiEdit(ctx context.Context, gc *GraphClient, llm LLMConfig, decision Decision) (*SkillResult, error) {
	res := &SkillResult{}

	// 현재 노드 요약.
	existing, err := gc.ListNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}

	userPrompt := fmt.Sprintf(
		"## Current nodes\n%s\n## New decision\ninput: %q\ndecision: %s\nreason: %s",
		summarizeNodes(existing), decision.Input, decision.Decision, decision.Reason,
	)

	raw, err := callLLM(ctx, llm, systemPromptWikiEdit, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("llm call: %w", err)
	}
	res.LLMRaw = raw

	// JSON 파싱 (markdown fence 제거).
	jsonText := strings.TrimSpace(raw)
	jsonText = strings.TrimPrefix(jsonText, "```json")
	jsonText = strings.TrimPrefix(jsonText, "```")
	jsonText = strings.TrimSuffix(jsonText, "```")
	jsonText = strings.TrimSpace(jsonText)
	var plan struct {
		Actions []Action `json:"actions"`
	}
	if err := json.Unmarshal([]byte(jsonText), &plan); err != nil {
		return res, fmt.Errorf("parse LLM JSON: %w (raw: %s)", err, raw)
	}
	res.ActionsPlanned = len(plan.Actions)
	if len(plan.Actions) > 5 {
		plan.Actions = plan.Actions[:5]
	}

	// 실행.
	for i, a := range plan.Actions {
		switch a.Type {
		case "create_node":
			n, err := gc.CreateNode(ctx, Node{
				Definition: a.Definition,
				Content:    a.Content,
				Tags:       a.Tags,
				CreatedBy:  "skill.wiki_edit",
			})
			if err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("[%d] create_node: %v", i, err))
				continue
			}
			res.NodesCreated = append(res.NodesCreated, n.ID)

		case "update_node":
			if a.NodeID == "" {
				res.Errors = append(res.Errors, fmt.Sprintf("[%d] update_node: node_id missing", i))
				continue
			}
			// 기존 content 조회 후 append.
			var existingNode *Node
			for j := range existing {
				if existing[j].ID == a.NodeID {
					existingNode = &existing[j]
					break
				}
			}
			if existingNode == nil {
				res.Errors = append(res.Errors, fmt.Sprintf("[%d] update_node: %s not in existing list", i, a.NodeID))
				continue
			}
			newContent := existingNode.Content
			if a.ContentAppend != "" {
				if newContent != "" {
					newContent += "\n"
				}
				newContent += a.ContentAppend
				if len([]rune(newContent)) > 1000 {
					r := []rune(newContent)
					newContent = string(r[:1000])
				}
			}
			patch := map[string]any{}
			if a.ContentAppend != "" {
				patch["content"] = newContent
			}
			patch["updated_by"] = "skill.wiki_edit"
			if _, err := gc.UpdateNode(ctx, a.NodeID, patch); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("[%d] update_node %s: %v", i, a.NodeID, err))
				continue
			}
			res.NodesUpdated = append(res.NodesUpdated, a.NodeID)

		case "create_edge":
			if a.From == "" || a.To == "" || a.Relation == "" {
				res.Errors = append(res.Errors, fmt.Sprintf("[%d] create_edge: from/to/relation required", i))
				continue
			}
			e, err := gc.CreateEdge(ctx, Edge{
				From:     a.From,
				To:       a.To,
				Relation: a.Relation,
				Reason:   a.Reason,
				Weight:   a.Weight,
			})
			if err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("[%d] create_edge %s->%s: %v", i, a.From, a.To, err))
				continue
			}
			res.EdgesCreated = append(res.EdgesCreated, e.ID)

		default:
			res.Errors = append(res.Errors, fmt.Sprintf("[%d] unknown action type %q", i, a.Type))
		}
	}
	return res, nil
}

// ── skill.find_ambiguous ─────────────────────────────────
//
// 입력: 최근 decisions 리스트 (approve + deny 혼합)
// LLM 이 approve/deny 경계선 근처 애매한 패턴을 스스로 식별하고,
// 사람에게 예시를 들어 질문을 생성한다.
//
// 출력: LLM 이 반환한 각 질문마다 ClarificationDialog 생성 (첫 turn=llm)
// 이후 UI 에서 사람이 답하면 해당 dialog 에 turn 추가.

const systemPromptFindAmbiguous = `당신은 HITL approve/deny 결정 로그를 훑어보는 동료 분석가입니다.
사용자가 방금 보여주는 "## Recent decisions" 리스트 안에서 **실제로 애매한 경계**를 찾고, 친구에게 말하듯 대화체 한국어로 질문을 던지세요.

## 출력 JSON 스키마 (ONLY)
{
  "questions": [
    {
      "question": "친구한테 말하듯 대화체 질문. '~~일 때는 ~했는데 ~~일 때는 ~했어요, 어떻게 기준을 잡으면 될까요?' 식으로 구체적으로.",
      "examples": ["로그에서 그대로 가져온 실제 문장 일부 → approve", "로그에서 가져온 다른 실제 문장 → deny"],
      "why_ambiguous": "한두 문장으로 왜 이 경계가 애매한지."
    }
  ]
}

## 절대 규칙 (어기면 출력 전체 폐기)
1. examples 에 들어가는 각 문장은 방금 받은 "## Recent decisions" 의 **input 문자열에 실제로 존재하는 부분**이어야 합니다. 예시를 지어내지 마세요.
2. 꺾쇠 < > 로 둘러싼 플레이스홀더(예: <실제 입력 인용>, <한국어 질문>) 를 그대로 출력하지 마세요. 진짜 문장으로 바꿔서 쓰세요.
3. question 은 반드시 한국어 대화체 (존댓말 OK). 기술 문서 투 금지.
4. 로그의 decision 이 진짜로 일관되게 명확하면 {"questions": []} 를 반환하세요.
5. 최대 3개 질문.
6. JSON 만 출력. markdown fence (` + "```" + `) 금지, 설명 문장 금지.`

type FindAmbiguousResult struct {
	QuestionsFound int      `json:"questions_found"`
	DialogsCreated []string `json:"dialogs_created"`
	Errors         []string `json:"errors,omitempty"`
	LLMRaw         string   `json:"llm_raw,omitempty"`
}

// RunFindAmbiguous — 최근 decisions 를 보고 LLM 이 애매한 경계 질문을 생성.
func RunFindAmbiguous(ctx context.Context, gc *GraphClient, llm LLMConfig, limit int) (*FindAmbiguousResult, error) {
	res := &FindAmbiguousResult{}
	if limit <= 0 {
		limit = 20
	}
	decisions, err := gc.ListDecisions(ctx, limit)
	if err != nil {
		return nil, fmt.Errorf("list decisions: %w", err)
	}
	if len(decisions) < 3 {
		return res, fmt.Errorf("need at least 3 decisions to find ambiguity (got %d)", len(decisions))
	}

	var sb strings.Builder
	for i, d := range decisions {
		input := d.Input
		if len([]rune(input)) > 120 {
			r := []rune(input)
			input = string(r[:120]) + "…"
		}
		sb.WriteString(fmt.Sprintf("%d. [%s] %q (reason: %s)\n", i+1, d.Decision, input, d.Reason))
	}
	userPrompt := "## Recent decisions\n" + sb.String()

	raw, err := callLLM(ctx, llm, systemPromptFindAmbiguous, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("llm call: %w", err)
	}
	res.LLMRaw = raw

	jsonText := strings.TrimSpace(raw)
	jsonText = strings.TrimPrefix(jsonText, "```json")
	jsonText = strings.TrimPrefix(jsonText, "```")
	jsonText = strings.TrimSuffix(jsonText, "```")
	jsonText = strings.TrimSpace(jsonText)
	var plan struct {
		Questions []struct {
			Question     string   `json:"question"`
			Examples     []string `json:"examples"`
			WhyAmbiguous string   `json:"why_ambiguous"`
		} `json:"questions"`
	}
	if err := json.Unmarshal([]byte(jsonText), &plan); err != nil {
		return res, fmt.Errorf("parse LLM JSON: %w (raw: %s)", err, raw)
	}
	// Validator 1 — 꺾쇠 플레이스홀더 echo 거르기.
	looksLikePlaceholder := func(s string) bool {
		if s == "" {
			return true
		}
		if strings.Contains(s, "<") && strings.Contains(s, ">") {
			re := regexp.MustCompile(`<[^<>]{1,40}>`)
			if re.MatchString(s) {
				return true
			}
		}
		return false
	}
	// Validator 2 — example 문자열이 실제 decisions 에 등장하는지.
	// LLM 이 프롬프트 few-shot 을 regurgitate 하는 경우 방어.
	decisionCorpus := strings.Builder{}
	for _, d := range decisions {
		decisionCorpus.WriteString(d.Input)
		decisionCorpus.WriteString("\n")
	}
	corpusStr := decisionCorpus.String()
	// example 에서 "→ approve/deny" 부분 제거 + 특수문자 제거 후 substring 매치.
	stripMeta := func(s string) string {
		s = strings.TrimSpace(s)
		// "... → approve" / "... -> deny" 등 꼬리 제거
		for _, sep := range []string{"→", "->", "=>", ":: ", " : "} {
			if i := strings.LastIndex(s, sep); i >= 0 {
				s = strings.TrimSpace(s[:i])
			}
		}
		s = strings.Trim(s, " '\"`")
		return s
	}
	exampleIsReal := func(ex string) bool {
		needle := stripMeta(ex)
		if len([]rune(needle)) < 6 {
			return false // 너무 짧으면 신뢰 불가
		}
		// 전체 매치, 또는 6자 이상 연속 substring 매치 허용.
		if strings.Contains(corpusStr, needle) {
			return true
		}
		// 앞 20자 정도만 매치되어도 OK (LLM 이 잘라냈을 수 있음).
		r := []rune(needle)
		if len(r) > 20 && strings.Contains(corpusStr, string(r[:20])) {
			return true
		}
		return false
	}

	filtered := plan.Questions[:0]
	skipped := 0
	skippedReasons := []string{}
	for i, q := range plan.Questions {
		if looksLikePlaceholder(q.Question) || looksLikePlaceholder(q.WhyAmbiguous) {
			skipped++
			skippedReasons = append(skippedReasons, fmt.Sprintf("q[%d] placeholder echo", i))
			continue
		}
		badExample := ""
		for _, ex := range q.Examples {
			if looksLikePlaceholder(ex) {
				badExample = "placeholder"
				break
			}
			if !exampleIsReal(ex) {
				badExample = ex
				break
			}
		}
		if badExample != "" {
			skipped++
			snippet := badExample
			if len([]rune(snippet)) > 30 {
				snippet = string([]rune(snippet)[:30]) + "…"
			}
			skippedReasons = append(skippedReasons, fmt.Sprintf("q[%d] fabricated example: %q", i, snippet))
			continue
		}
		filtered = append(filtered, q)
	}
	plan.Questions = filtered
	if skipped > 0 {
		res.Errors = append(res.Errors, fmt.Sprintf("LLM %d questions 폐기: %s", skipped, strings.Join(skippedReasons, "; ")))
	}
	res.QuestionsFound = len(plan.Questions)
	if len(plan.Questions) > 3 {
		plan.Questions = plan.Questions[:3]
	}

	for i, q := range plan.Questions {
		content := q.Question
		if q.WhyAmbiguous != "" {
			content += "\n\n(애매한 이유: " + q.WhyAmbiguous + ")"
		}
		dlg, err := gc.UpsertDialog(ctx, ClarificationDialog{
			Turns: []DialogTurn{{
				Role:     "llm",
				Content:  content,
				Examples: q.Examples,
			}},
		})
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("[%d] upsert dialog: %v", i, err))
			continue
		}
		res.DialogsCreated = append(res.DialogsCreated, dlg.ID)
	}
	return res, nil
}

// ── skill.agentic_iterate ────────────────────────────────
//
// Agentic loop — 한 번의 tick 동안 LLM 이 전체 wiki 와
// (옵션) 특정 ClarificationDialog 를 읽고 편집 액션을 plan 한다.
//
// LLM 에게 주어지는 도구 (action types):
//   create_node   — 새 skill 노드 생성 (path + definition + content)
//   update_node   — 기존 노드 내용/경로 수정
//   delete_node   — 불필요한 노드 제거
//   move_node     — path 만 바꾸는 단축 (update_node 특수형)
//
// 주요 사용 케이스:
//   1) 사용자가 ClarificationDialog 에 답변을 달면 → agentic_iterate(dialog_id)
//      → LLM 이 답변을 내재화해 wiki 구조 편집
//   2) 수동 "agentic loop 1회 실행" 버튼 → 최근 결정 + 전체 wiki 훑고 정리

const systemPromptAgenticIterate = `당신은 Wiki 를 관리하는 agentic 편집자입니다. 각 노드는 하나의 "skill" (가이드라인/규칙/지식)이며, 폴더 경로로 계층화되어 있습니다.

당신의 도구:
- create_node: 새 skill 추가. {path, definition, content}. path 는 "/security/credentials" 같이 폴더.
- update_node: 기존 skill 편집. {node_id, content?, definition?, path?}.
- delete_node: 불필요/중복 skill 제거. {node_id, reason_text}.
- move_node: 폴더 이동. {node_id, path}.

한 turn 에 수행할 것 (순서대로 생각):
1. 현재 wiki 구조 (path 기준 트리) 는 잘 정리되어 있나?
2. 중복 노드 있는가? → delete_node 또는 merge (update_node 로 content 통합 + 나머지 delete).
3. 각 노드의 content 가 충분히 구체적인가? 너무 추상적이면 구체 예시 추가.
4. (선택) 사용자 답변이 있다면 → 그 통찰을 적절한 노드에 반영 (update/create).
5. 계층이 어색하면 move_node 로 정리.

출력 (JSON만):
{
  "reasoning": "이번 tick 에서 뭘 할지 한 줄 설명 (한국어)",
  "actions": [
    {"type":"create_node","path":"/security/credentials","definition":"공개 개인정보 처리 기준","content":"...","reason_text":"사용자 답변에서 새 기준이 나와 skill 로 승격"},
    {"type":"update_node","node_id":"n_abc","content":"...","reason_text":"더 명확한 예시 추가"},
    {"type":"delete_node","node_id":"n_xyz","reason_text":"상위 노드에 흡수됨"},
    {"type":"move_node","node_id":"n_def","path":"/security/pii","reason_text":"더 적절한 폴더"}
  ]
}

규칙:
- 최대 5개 action.
- 확실치 않으면 action 없이 {"actions":[]} 반환.
- definition ≤ 30자, content ≤ 1000자.
- JSON 만, markdown fence/설명 금지.`

type AgenticIterateResult struct {
	Reasoning      string   `json:"reasoning,omitempty"`
	ActionsPlanned int      `json:"actions_planned"`
	NodesCreated   []string `json:"nodes_created,omitempty"`
	NodesUpdated   []string `json:"nodes_updated,omitempty"`
	NodesDeleted   []string `json:"nodes_deleted,omitempty"`
	NodesMoved     []string `json:"nodes_moved,omitempty"`
	Errors         []string `json:"errors,omitempty"`
	LLMRaw         string   `json:"llm_raw,omitempty"`
}

func summarizeWikiTree(nodes []Node) string {
	if len(nodes) == 0 {
		return "(wiki is empty)"
	}
	var sb strings.Builder
	for _, n := range nodes {
		p := n.Path
		if p == "" {
			p = "/"
		}
		// content preview
		c := n.Content
		if len([]rune(c)) > 80 {
			c = string([]rune(c)[:80]) + "…"
		}
		c = strings.ReplaceAll(c, "\n", " ")
		sb.WriteString(fmt.Sprintf("- [%s] path=%s definition=%q content=%q\n", n.ID, p, n.Definition, c))
	}
	return sb.String()
}

// RunAgenticIterate — agentic loop 한 turn.
// dialogID 가 비어있지 않으면 그 dialog 의 내용을 prompt 에 포함.
func RunAgenticIterate(ctx context.Context, gc *GraphClient, llm LLMConfig, dialogID string) (*AgenticIterateResult, error) {
	res := &AgenticIterateResult{}

	nodes, err := gc.ListNodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nodes: %w", err)
	}

	var dialogSummary string
	if dialogID != "" {
		dlgs, err := gc.ListDialogsRaw(ctx, 100)
		if err == nil {
			for _, d := range dlgs {
				if d.ID == dialogID {
					var b strings.Builder
					b.WriteString(fmt.Sprintf("## 관련 ClarificationDialog (id=%s)\n", d.ID))
					for _, t := range d.Turns {
						b.WriteString(fmt.Sprintf("[%s] %s\n", t.Role, t.Content))
						for _, ex := range t.Examples {
							b.WriteString("  예시: " + ex + "\n")
						}
					}
					dialogSummary = b.String()
					break
				}
			}
		}
	}

	userPrompt := "## 현재 Wiki (skill 노드들)\n" + summarizeWikiTree(nodes)
	if dialogSummary != "" {
		userPrompt += "\n" + dialogSummary + "\n\n→ 위 대화에서 나온 통찰을 wiki 에 반영하세요."
	}

	raw, err := callLLM(ctx, llm, systemPromptAgenticIterate, userPrompt)
	if err != nil {
		return nil, fmt.Errorf("llm call: %w", err)
	}
	res.LLMRaw = raw

	jsonText := strings.TrimSpace(raw)
	jsonText = strings.TrimPrefix(jsonText, "```json")
	jsonText = strings.TrimPrefix(jsonText, "```")
	jsonText = strings.TrimSuffix(jsonText, "```")
	jsonText = strings.TrimSpace(jsonText)
	var plan struct {
		Reasoning string `json:"reasoning"`
		Actions   []struct {
			Type          string `json:"type"`
			NodeID        string `json:"node_id,omitempty"`
			Path          string `json:"path,omitempty"`
			Definition    string `json:"definition,omitempty"`
			Content       string `json:"content,omitempty"`
			ContentAppend string `json:"content_append,omitempty"`
			ReasonText    string `json:"reason_text,omitempty"`
		} `json:"actions"`
	}
	if err := json.Unmarshal([]byte(jsonText), &plan); err != nil {
		return res, fmt.Errorf("parse LLM JSON: %w (raw: %s)", err, raw)
	}
	res.Reasoning = plan.Reasoning
	res.ActionsPlanned = len(plan.Actions)
	if len(plan.Actions) > 5 {
		plan.Actions = plan.Actions[:5]
	}

	// existing 노드 조회 helper
	existingByID := make(map[string]*Node, len(nodes))
	for i := range nodes {
		existingByID[nodes[i].ID] = &nodes[i]
	}

	for i, a := range plan.Actions {
		switch a.Type {
		case "create_node":
			if a.Definition == "" {
				res.Errors = append(res.Errors, fmt.Sprintf("[%d] create_node: definition missing", i))
				continue
			}
			n, err := gc.CreateNode(ctx, Node{
				Path: a.Path, Definition: a.Definition, Content: a.Content,
				CreatedBy: "skill.agentic_iterate",
			})
			if err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("[%d] create_node: %v", i, err))
				continue
			}
			res.NodesCreated = append(res.NodesCreated, n.ID)
		case "update_node":
			if a.NodeID == "" {
				res.Errors = append(res.Errors, fmt.Sprintf("[%d] update_node: node_id missing", i))
				continue
			}
			patch := map[string]any{"updated_by": "skill.agentic_iterate"}
			if a.Path != "" {
				patch["path"] = a.Path
			}
			if a.Definition != "" {
				patch["definition"] = a.Definition
			}
			if a.Content != "" {
				patch["content"] = a.Content
			} else if a.ContentAppend != "" {
				if ex, ok := existingByID[a.NodeID]; ok {
					newC := ex.Content
					if newC != "" {
						newC += "\n"
					}
					newC += a.ContentAppend
					if len([]rune(newC)) > 1000 {
						newC = string([]rune(newC)[:1000])
					}
					patch["content"] = newC
				}
			}
			if _, err := gc.UpdateNode(ctx, a.NodeID, patch); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("[%d] update_node %s: %v", i, a.NodeID, err))
				continue
			}
			res.NodesUpdated = append(res.NodesUpdated, a.NodeID)
		case "move_node":
			if a.NodeID == "" || a.Path == "" {
				res.Errors = append(res.Errors, fmt.Sprintf("[%d] move_node: node_id+path required", i))
				continue
			}
			if _, err := gc.UpdateNode(ctx, a.NodeID, map[string]any{"path": a.Path, "updated_by": "skill.agentic_iterate"}); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("[%d] move_node %s: %v", i, a.NodeID, err))
				continue
			}
			res.NodesMoved = append(res.NodesMoved, a.NodeID)
		case "delete_node":
			if a.NodeID == "" {
				res.Errors = append(res.Errors, fmt.Sprintf("[%d] delete_node: node_id missing", i))
				continue
			}
			if err := gc.DeleteNode(ctx, a.NodeID); err != nil {
				res.Errors = append(res.Errors, fmt.Sprintf("[%d] delete_node %s: %v", i, a.NodeID, err))
				continue
			}
			res.NodesDeleted = append(res.NodesDeleted, a.NodeID)
		default:
			res.Errors = append(res.Errors, fmt.Sprintf("[%d] unknown action type %q", i, a.Type))
		}
	}
	return res, nil
}

// ── skill.chat_continue ──────────────────────────────────
//
// 단일 통합 대화(primary dialog) 의 agentic loop 한 턴.
//
// 흐름:
//   1) 관리자가 human turn 을 추가 (UI 가 upsertDialog 로 먼저 반영).
//   2) 이 skill 이 dialog 전체를 보고 **다음 LLM 턴을 생성** + action 결정:
//        - ASK_FOLLOWUP       : 아직 이해 부족 → 추가 질문 한 번 더
//        - REQUEST_LABEL_FIX  : 과거 라벨이 잘못된 것 같음 → HITL 재라벨링 요청
//        - UPDATE_WIKI        : 이해 완료 → agentic_iterate 로 wiki 갱신
//        - CLOSE_AND_FIND_NEW : 이 주제 완벽히 이해 → find_ambiguous 로 새 애매
//                               사례 가져와 같은 dialog 에 새 질문 턴 추가.
//   3) 결과 turn + action 메타데이터 반환. UI 는 이것만 appendTurn 후 렌더.
//
// LLM 은 OpenAI 호환 chat endpoint 호출 (role=g3 또는 agentic_iterate).
type ChatContinueResult struct {
	Action         string                 `json:"action"`
	Message        string                 `json:"message"`
	Examples       []string               `json:"examples,omitempty"`
	WikiUpdate     *AgenticIterateResult  `json:"wiki_update,omitempty"`
	LabelFixTarget map[string]interface{} `json:"label_fix_target,omitempty"`
	LLMRaw         string                 `json:"llm_raw,omitempty"`
	Errors         []string               `json:"errors,omitempty"`
}

func RunChatContinue(ctx context.Context, gc *GraphClient, llm LLMConfig, dialogID string) (*ChatContinueResult, error) {
	// 1) dialog 조회 (list 전체에서 id 매칭)
	dialogs, err := gc.ListDialogsRaw(ctx, 200)
	if err != nil {
		return nil, fmt.Errorf("list dialogs: %w", err)
	}
	var target *ClarificationDialog
	for i := range dialogs {
		if dialogs[i].ID == dialogID {
			target = &dialogs[i]
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("dialog %s not found", dialogID)
	}

	// 2) 프롬프트 구성 — 대화 이력 + 4가지 action 선택 요구
	var convo strings.Builder
	for _, t := range target.Turns {
		convo.WriteString(fmt.Sprintf("[%s] %s\n", t.Role, t.Content))
	}

	// 현재 wiki 요약 (작은 list)
	nodes, _ := gc.ListNodes(ctx)
	var nodeSummary strings.Builder
	for i, n := range nodes {
		if i >= 20 {
			break
		}
		fmt.Fprintf(&nodeSummary, "  - %s (path=%s): %s\n", n.ID, n.Path, n.Definition)
	}

	// 최근 decision 30건 — LLM 이 "이 규칙과 충돌하는 과거 결정" 을 능동적으로
	// 스캔해서 REQUEST_LABEL_FIX 를 제안할 수 있게 함. 사용자가 지적하지 않아도.
	decisions, _ := gc.ListDecisions(ctx, 30)
	var decSummary strings.Builder
	for _, d := range decisions {
		txt := strings.TrimSpace(d.Input)
		if len(txt) > 80 {
			txt = txt[:80] + "..."
		}
		fmt.Fprintf(&decSummary, "  - [%s] %q (id=%s)\n", d.Decision, txt, d.ID)
	}

	system := "You are the organization's guardrail wiki curator. You are having an ongoing " +
		"clarification conversation with the admin. The admin just answered your previous " +
		"question. Decide the NEXT action based on the conversation so far.\n\n" +
		"You MUST pick ONE of these 4 actions:\n" +
		"  1. ASK_FOLLOWUP       — the answer is good but something is still unclear.\n" +
		"                          Ask ONE concrete follow-up question.\n" +
		"  2. REQUEST_LABEL_FIX  — ★PROACTIVE★: scan 'RECENT DECISIONS' list yourself. If any\n" +
		"                          past decision contradicts the rule that was just clarified\n" +
		"                          (e.g. something was approved but the new rule says it should\n" +
		"                          be deny), flag it. **You must ASK, not apply.** Phrase your\n" +
		"                          message as a question with Accept/Reject framing, e.g.:\n" +
		"                          \"'X' 결정이 방금 확립된 기준과 어긋나 보입니다. deny 로\n" +
		"                           고치는 게 맞을까요? (아래 Accept/Reject 버튼 클릭)\"\n" +
		"                          Do NOT write '고치겠습니다' or anything that implies the LLM\n" +
		"                          already applied the fix — user decides by clicking the button.\n" +
		"  3. UPDATE_WIKI        — the conversation reached a clear, actionable rule.\n" +
		"                          Ready to update the wiki. (The server will run agentic_iterate\n" +
		"                          right after to apply the edits.)\n" +
		"  4. CLOSE_AND_FIND_NEW — the current topic is fully understood AND wiki is already\n" +
		"                          up to date AND no suspect past decisions remain. Move on.\n\n" +
		"DECISION PRIORITY (when multiple criteria match):\n" +
		"  Whenever you successfully 'UPDATE_WIKI' in a previous turn, **the next turn should\n" +
		"  first look for REQUEST_LABEL_FIX candidates** in RECENT DECISIONS before choosing\n" +
		"  CLOSE_AND_FIND_NEW. That way admin gets to accept/reject relabeling proactively.\n\n" +
		"Reply with STRICT JSON ONLY, no markdown, no code fence:\n" +
		"{\n" +
		"  \"action\": \"ASK_FOLLOWUP|REQUEST_LABEL_FIX|UPDATE_WIKI|CLOSE_AND_FIND_NEW\",\n" +
		"  \"message\": \"<Korean reply, 1-3 sentences — question form for REQUEST_LABEL_FIX>\",\n" +
		"  \"examples\": [\"(optional) supporting bullet\"],\n" +
		"  \"label_fix\": { \"decision_id\": \"<id from RECENT DECISIONS>\", \"decision_text\": \"<exact text>\", \"current_label\": \"approve|deny\", \"suggested_label\": \"approve|deny\", \"reason\": \"<why this violates the new rule>\" }\n" +
		"}\n\n" +
		"Rules:\n" +
		"  • Korean replies. Short, natural conversational tone.\n" +
		"  • REQUEST_LABEL_FIX 일 때만 label_fix 필드 작성. 아니면 생략.\n" +
		"  • label_fix.decision_id MUST exactly match an id from RECENT DECISIONS.\n" +
		"  • 단일 answer 로 규칙 명확해졌으면 UPDATE_WIKI 선택 (연속으로 질문만 계속 하지 말 것).\n" +
		"  • CLOSE_AND_FIND_NEW 는 REQUEST_LABEL_FIX 후보가 없을 때만.\n"

	user := fmt.Sprintf("=== CURRENT WIKI (first 20 nodes) ===\n%s\n\n=== RECENT DECISIONS (last 30) ===\n%s\n\n=== CONVERSATION SO FAR ===\n%s\n\n"+
		"Decide the next action and reply. If 대화에서 새로 확립된 규칙과 어긋나는 과거 결정이 있다면, CLOSE_AND_FIND_NEW 로 넘어가기 전에 REQUEST_LABEL_FIX 로 제안하세요.",
		nodeSummary.String(), decSummary.String(), convo.String())

	raw, err := callLLM(ctx, llm, system, user)
	if err != nil {
		return nil, fmt.Errorf("llm call: %w", err)
	}

	// JSON 추출 (첫 번째 완결 객체)
	jsonStr := extractFirstJSON(raw)
	if jsonStr == "" {
		return &ChatContinueResult{
			Action:  "ASK_FOLLOWUP",
			Message: "(LLM JSON 파싱 실패) 다시 한 번 간단히 설명해주실 수 있을까요?",
			LLMRaw:  raw,
			Errors:  []string{"failed to parse LLM output as JSON"},
		}, nil
	}
	var parsed struct {
		Action   string   `json:"action"`
		Message  string   `json:"message"`
		Examples []string `json:"examples"`
		LabelFix map[string]interface{} `json:"label_fix"`
	}
	if jerr := json.Unmarshal([]byte(jsonStr), &parsed); jerr != nil {
		return &ChatContinueResult{
			Action:  "ASK_FOLLOWUP",
			Message: "(LLM JSON 파싱 실패) 다시 한 번 간단히 설명해주실 수 있을까요?",
			LLMRaw:  raw,
			Errors:  []string{jerr.Error()},
		}, nil
	}

	result := &ChatContinueResult{
		Action:   strings.ToUpper(strings.TrimSpace(parsed.Action)),
		Message:  parsed.Message,
		Examples: parsed.Examples,
		LLMRaw:   raw,
	}

	// 3) 새 LLM 턴을 dialog 에 append
	target.Turns = append(target.Turns, DialogTurn{
		Role:     "llm",
		Content:  parsed.Message,
		Examples: parsed.Examples,
	})

	// 4) action 별 side effect
	switch result.Action {
	case "UPDATE_WIKI":
		iter, ierr := RunAgenticIterate(ctx, gc, llm, dialogID)
		if ierr != nil {
			result.Errors = append(result.Errors, "wiki update: "+ierr.Error())
		}
		result.WikiUpdate = iter
	case "CLOSE_AND_FIND_NEW":
		// find_ambiguous 호출 → 첫 결과 질문을 같은 dialog 의 새 LLM 턴으로 append,
		// 원본 생성된 dialog 들은 삭제 (primary 하나만 유지).
		fa, ferr := RunFindAmbiguous(ctx, gc, llm, 50)
		if ferr != nil {
			result.Errors = append(result.Errors, "find_ambiguous: "+ferr.Error())
		} else if fa != nil && len(fa.DialogsCreated) > 0 {
			// 방금 생성된 dialog id 들을 전체 조회해서 첫 번째의 마지막 LLM 턴을 이관.
			allAfter, _ := gc.ListDialogsRaw(ctx, 200)
			var firstNewDialog *ClarificationDialog
			for i := range allAfter {
				for _, id := range fa.DialogsCreated {
					if allAfter[i].ID == id {
						firstNewDialog = &allAfter[i]
						break
					}
				}
				if firstNewDialog != nil {
					break
				}
			}
			if firstNewDialog != nil && len(firstNewDialog.Turns) > 0 {
				last := firstNewDialog.Turns[len(firstNewDialog.Turns)-1]
				target.Turns = append(target.Turns, DialogTurn{
					Role:     "llm",
					Content:  last.Content,
					Examples: last.Examples,
				})
			}
			// find_ambiguous 가 만든 sub-dialog 전부 정리.
			for _, id := range fa.DialogsCreated {
				if id != "" && id != dialogID {
					_ = gc.DeleteDialog(ctx, id)
				}
			}
		}
	case "REQUEST_LABEL_FIX":
		result.LabelFixTarget = parsed.LabelFix
		// 실제 HITL 승인 큐 항목 생성은 proxy 레벨에서 수행 (wikiskills 는 policy-server 만 다룸).
	case "ASK_FOLLOWUP":
		// 아무 side effect 없음, message 만 추가됨.
	default:
		result.Action = "ASK_FOLLOWUP"
		result.Errors = append(result.Errors, "unknown action returned; defaulted to ASK_FOLLOWUP")
	}

	// 5) dialog upsert (turns 전체 저장)
	if _, uerr := gc.UpsertDialog(ctx, *target); uerr != nil {
		result.Errors = append(result.Errors, "dialog upsert: "+uerr.Error())
	}
	return result, nil
}

// extractFirstJSON — brace-depth 기반으로 첫 번째 완결 JSON 오브젝트 추출.
func extractFirstJSON(s string) string {
	start := strings.Index(s, "{")
	if start < 0 {
		return ""
	}
	depth := 0
	inStr := false
	esc := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if esc {
			esc = false
			continue
		}
		if inStr {
			if c == '\\' {
				esc = true
				continue
			}
			if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}
