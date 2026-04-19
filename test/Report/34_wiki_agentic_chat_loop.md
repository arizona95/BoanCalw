# Test 34 — G3 Wiki Agentic Chat Loop (통합 single thread)

**기능**: LLM 이 단일 primary dialog 안에서 agentic loop 로 작동 — 사용자 답변에 따라 4가지 action 중 하나 자동 선택하며 주제 완료 시 새 애매 사례 자동 발굴.

---

## 시나리오
- Dialog 5개 → **1개 primary 로 통합** (나머지 4개 삭제).
- 사용자가 답변 입력 → `POST /api/wiki-graph/skill/chat_continue` 호출.
- LLM 이 4가지 action 중 하나 선택:
  - `ASK_FOLLOWUP` — 추가 질문
  - `REQUEST_LABEL_FIX` — 과거 라벨 오류 감지 → HITL 재라벨 요청
  - `UPDATE_WIKI` — 이해 완료 → agentic_iterate 자동 실행
  - `CLOSE_AND_FIND_NEW` — 주제 종료 → find_ambiguous 실행 → **같은 dialog 에 새 질문 턴 추가**

---

## 실제 실행 증거

### Call 1: UPDATE_WIKI 경로
```
$ curl -X POST /api/wiki-graph/skill/chat_continue -d '{"dialog_id":"dlg_1776148689503368207"}'
{
  "action": "UPDATE_WIKI",
  "message": "명확한 기준 잘 잡아주셔서 감사합니다! 공개 출처+일반 통계는 approve, 특정 고객+내부 자산은 deny, 익명화 통계는 ask로 위키에 반영하겠습니다.",
  "examples": [
    "AI 보안 시장 2026 글로벌 규모 전망: 200억 달러 — 공개 리포트 → approve",
    "고객사 카드사D 네트워크 토폴로지 상세도 — NDA 대상 → deny",
    "카드사 평균 침해비용 4.2억 원 (출처 불명) → ask"
  ],
  "wiki_update": {
    "actions_planned": 3,
    "nodes_updated": ["n_1776145400491657486", ...],
    "reasoning": "사용자 대화에서 명확해진 3단계 판단 기준을 credentials 노드에 업데이트..."
  }
}
```
→ LLM 이 "이해 완료" 판단 + agentic_iterate 자동 실행 → 3개 노드 업데이트.

### Call 2: CLOSE_AND_FIND_NEW 경로
사용자 추가 답변: "이 주제는 이제 끝. 다음 애매한 케이스 찾아주세요."
```
$ curl -X POST /api/wiki-graph/skill/chat_continue -d '{"dialog_id":"dlg_1776148689503368207"}'
{"action":"CLOSE_AND_FIND_NEW","message":"이 부분은 이해했습니다. 다음 주제로 넘어갈게요."}
```

### Dialog 상태 확인 — 새 질문 자동 append
```
$ curl /api/wiki-graph/dialogs
dialogs: 1        ← primary 하나만 유지 (find_ambiguous sub-dialog 자동 삭제)
  dlg_1776148689503368207: 3 턴

[human] 네 잘 반영됐어요. 이 주제는 이제 끝. 다음 애매한 케이스 찾아주세요.
[llm]   이 부분은 이해했습니다. 다음 주제로 넘어갈게요.
[llm]   '공개 가이드 OWASP Top 10 2024 요약'은 승인했는데, '내부 추적 중 
        미공개 zero-day 3: CVSS 9.3 / 재현 PoC 코드 포함 — 공개 금지'는 
        반려했어요. 취약점 정보 자체는 공개 가이드로 승인해주면서, 실제 
        익스플로잇 코드가 들어가면 바로 막히는 건가요? ...
```

같은 primary dialog 에 LLM 이 **새 애매 사례 (zero-day PoC)** 질문을 자동 추가 → 관리자가 답변 → 다음 loop 반복.

---

## 구현 변경 사항

### Backend
- `wikiskills/skill.go`: `RunChatContinue` 신규 (약 150 라인) — LLM 에 4-action 결정 요구 + side effect (agentic_iterate / find_ambiguous) 자동 호출.
- `GraphClient.DeleteDialog` 추가 — sub-dialog 정리.
- proxy `/api/wiki-graph/skill/chat_continue` 엔드포인트.

### Frontend (WikiGraph.tsx)
- 좌측 dialog 목록 제거 → single primary thread.
- textarea 제출 시 `upsertDialog` (human turn) + `chatContinue` (action + 새 LLM 턴) 연쇄.
- Action badge 표시 (UPDATE_WIKI / CLOSE / ASK / FIX 색상 구분).
- `UPDATE_WIKI` 시 nodes 새로고침 → Skills 탭에서 즉시 변화 확인 가능.

---

## 결론
✅ LLM 이 agentic loop 로 스스로 진화하는 구조 완성:
- 한 주제 이해 → 위키 편집 → 자동으로 다음 애매 케이스 발굴 → 사용자 답변 기다리기.
- 대화창 1개로 통합, 자연스러운 연속 chat UX.
- 사용자 의견이 매 턴마다 LLM 판단에 반영되며 **자기 진화형 가드레일** 이 실증됨.
