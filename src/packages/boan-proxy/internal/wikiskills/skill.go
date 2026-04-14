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
	}
	raw, _ := json.Marshal(reqBody)
	// HTTP_PROXY 무시.
	httpClient := &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{Proxy: nil}}
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
		limit = 50
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
