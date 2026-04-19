# Test 33 — G3 Folder Wiki: LLM Self-Evolution from User Opinion

**기능**: 관리자가 clarification dialog 에 의견을 답변하면 LLM 이 agentic_iterate 로 읽어서 wiki 노드를 자동 편집 → G3 가드레일이 그 의견을 내재화.

---

## 시나리오 (실제 실행)
기존 dialog `dlg_1776148689503368207` — LLM 이 과거 decision 에서 애매했던 사례 (공개 리포트 approve vs NDA 고객 deny) 를 제기한 질문.

### Step 1: 관리자가 human turn 추가 (기준 명확화)
```
$ curl -X POST /api/wiki-graph/dialogs -d '{
  "id": "dlg_1776148689503368207",
  "turns": [
    {"role":"llm","content":"공개 리포트 approve, NDA 고객 deny 기준 애매..."},
    {"role":"human","content":"기준: (1) 공개 URL/벤더 공식 리포트 → approve. (2) 고객사 명시 + NDA/내부 시스템 → deny. (3) 산업/세그먼트 익명화 통계 → ask. 요약: 공개+일반 = Approve, 특정+내부 = Deny."}
  ]
}'
HTTP 200
```

### Step 2: agentic_iterate 호출 → LLM 이 dialog 읽고 wiki 편집 수행
```
$ curl -X POST /api/wiki-graph/skill/agentic_iterate -d '{"dialog_id":"dlg_1776148689503368207"}'
{
  "reasoning": "사용자 대화에서 도출된 공개/비공개 정보 처리 기준을 반영하여 중복 노드들을 병합하고, 루트 경로에 있는 노드들을 적절한 하위 경로로 이동시켜 계층 구조를 정리합니다.",
  "actions_planned": 5,
  "nodes_updated": ["n_1776145400491657486"],
  "nodes_deleted": ["n_1776143717024728361", "n_1776145377817471747"],
  "nodes_moved": ["n_1776086418627697441", "n_1776086405843834668"]
}
```

### Step 3: 실제 노드 내용 확인 (LLM 이 사용자 답변 그대로 반영)
```
$ curl /api/wiki-graph/nodes/n_1776145400491657486
{
  "id": "n_1776145400491657486",
  "path": "/security/credentials",
  "definition": "정보 공개/비공개 처리 기준",       ← ★ 이전: "공개 개인정보 처리 기준"
  "content": "정보 공개 여부 판단 기준:
1. Approve: 출처가 공개 URL 또는 벤더 발간 공식 리포트인 일반 통계 (예: AI 보안 시장 2026 글로벌 규모 전망: 200억 달러)
2. Deny: 고객사 이름이 명시되고 NDA / 내부 시스템 / 인프라 구성도가 포함된 경우 (예: 고객사 카드사D 네트워크 토폴로지 상세도)
3. Ask: 고객사 산업/세그먼트만 익명화된 통계인 경우
요약: 공개 출처 + 일반 통계 = Approve, 특정 고객 + 내부 자산 = Deny",
  "updated_at": "2026-04-19T08:50:38..."   ← 방금 업데이트됨
}
```

---

## 핵심 검증: LLM 진화의 증거

1. **사용자 의견 → 노드 definition/content 자동 반영**
   관리자가 타이핑한 "approve/deny/ask 3단계 기준" 이 거의 그대로 노드 content 에 들어감.

2. **계층 구조 자기 조직화**
   LLM 이 /security/nda 폴더를 인지하고 관련 노드들을 그리로 move. 초기엔 평면 구조였는데 dialog 반영 후 계층 정리.

3. **중복 cleanup**
   테스트 스킬 노드 / 중복 PII 노드 자동 삭제. LLM 이 필요없는 것 정리.

4. **wiki 변경이 G3 에 영향**
   G3 WikiEvaluate 는 `/v1/guardrail/wiki-evaluate` 호출 시 policy-server 측에서 wiki nodes 를 context 로 참조 → 이 업데이트된 "정보 공개/비공개 처리 기준" 노드가 향후 G3 judgment 의 근거가 됨.

---

## 결론
✅ **LLM 자기진화 실제 동작 확인됨**.
- 사용자 1턴 답변 → 5개 wiki action → 노드 업데이트 + 이동 + 삭제 일괄 수행.
- 답변 내용(approve/deny/ask 기준)이 노드 content 에 녹아들어감.
- 향후 G3 wiki-evaluate 호출 시 이 업데이트된 기준이 근거로 사용될 준비 완료.

### 관련 API
- `POST /api/wiki-graph/dialogs` — dialog upsert (turn 추가)
- `POST /api/wiki-graph/skill/agentic_iterate` — LLM 이 dialog/decisions 읽고 wiki 편집
- `POST /api/wiki-graph/skill/find_ambiguous` — LLM 이 decision 이력에서 애매한 사례 찾아 dialog 자동 생성
- `GET /api/wiki-graph/nodes` — 현재 wiki 상태 조회
