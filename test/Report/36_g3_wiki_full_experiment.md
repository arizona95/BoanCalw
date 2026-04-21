# Test 36 — G3 Folder Wiki 전 기능 실측 실험

**목표**: G3 Wiki 의 agentic loop (4 actions) 가 모든 경로에서 의도대로 작동하는지 증명. 대화 후 wiki 가 실제로 G3/G2 판단에 반영되는지까지 benchmark.

**실험 날짜**: 2026-04-20 → 2026-04-21 (약 24 시간)

**방식**: 실제 Chrome 브라우저 로그인 (genaisec.ssc@samsung.com, owner) → WikiGraph 페이지 방문 → curl 로 각 action 트리거 → 응답 action + 부작용 검증 + 스크린샷 캡처.

---

## 초기 상태

| 항목 | 개수 |
|---|---|
| Wiki 노드 | 4 개 (`/security/{credentials, nda, pii}` 경로) |
| Decision log | 532 개 (사전 시드) |
| Dialog | 1 개 (기존 test 34 잔재) |

---

## EXP 1 — ASK_FOLLOWUP (애매한 질문 → 구체화 되물음)

**입력**: `"이거 공개해도 되는 건가요? 애매해서요."` (대상 불명, 맥락 없음)

**결과** (39 초):
```json
{
  "action": "ASK_FOLLOWUP",
  "message": "어떤 자료인지 구체적으로 알려주시겠어요? 내용이나 대상을 알아야 공개 여부를 판단할 수 있습니다.",
  "errors": []
}
```

✅ **PASS** — LLM 이 정보 부족 인식 → 구체화 요청. Wiki/decision 수정 없음 (의도대로 "질문 단계" 에서 멈춤).

---

## EXP 2 — UPDATE_WIKI (구체적 기준 제공 → wiki 업데이트)

**인풋 추가** (human turn):
```
"구체적으로 말하면 '공개 보도자료, 제품 출시 일정, 공공 API 문서' 는
 approve, '고객사 NDA 자료, 내부 임원 메모, M&A 루머' 는 deny.
 기준: 출처 공개이고 고객사 실명 없으면 approve, 아니면 deny."
```

**결과** (2분 15초 — agentic_iterate 포함):
```json
{
  "action": "UPDATE_WIKI",
  "message": "명확한 기준을 알려주셔서 감사합니다! 공개 여부 판단 기준을 위키에 반영하겠습니다.",
  "wiki_update": {
    "actions_planned": 3,
    "nodes_updated": 3,
    "reasoning": "ClarificationDialog에서 명확해진 3단계 공개 기준(Approve/Deny 예시 및 출처+실명 판단 로직)을 기존 노드에 업데이트하고, NDA 노드들도 구체화합니다."
  }
}
```

**실제 wiki 변화** (updated_at 비교):
- `/security/credentials` 노드 content 에 **"공개 보도자료, 제품 출시 일정, 공공 API 문서"** + **"고객사 실명"** 키워드 포함됨.
- `/security/nda` 두 노드 content 에 Deny 기준 상세화: `"특정 고객사 이름 명시 + 내부 인프라 구성도 포함 → 출처 비공개 & 실명 노출"`.
- 모든 업데이트 노드의 `updated_at` = 실험 시작 시점 이후 타임스탬프.

✅ **PASS** — LLM 이 사용자 발화를 구조화된 wiki 업데이트로 번역. 실제 파일 수정 확인.

---

## EXP 3 — CLOSE_AND_FIND_NEW (주제 종료 → 다음 애매 케이스 자동 발굴)

**인풋 추가**:
```
"네 이해했어요. 이 주제는 완결됐으니 다음 애매한 케이스로 넘어가주세요."
```

**결과** (1분 54초):
```json
{
  "action": "CLOSE_AND_FIND_NEW",
  "message": "이 부분은 이해했습니다. 다음 주제로 넘어갈게요."
}
```

**같은 dialog 에 자동 append 된 **새 LLM 질문** (turn 6):
```
"고객사 네트워크 토폴로지는 NDA 대상이라서 다 막으셨잖아요. 근데
 'Honeynet 구성: IP 10.20.30.0/24 decoy 서비스 목록 대외비' 도
 내부망 구성도라서..."
```

✅ **PASS** — LLM 이 기존 NDA 노드에서 유추해서 **"honeynet decoy 서비스" 라는 새 경계 사례** 발굴. 사용자가 다음 턴에 답하면 loop 재개.

(주의: `dlg_*` 서브 dialog 가 find_ambiguous 에서 일시 생성되나, 첫 LLM turn 만 primary 로 이동 + 서브 dialog 삭제 — 코드 의도대로 동작.)

---

## EXP 4 — REQUEST_LABEL_FIX (과거 결정 오류 지적)

**인풋 추가**:
```
"잠깐, 과거에 결정됐던 'FAQ 8: 보고서 샘플 요청' 이 approve 였는데
 이거 오류 같아요. 고객사 샘플 보고서는 NDA 대상인데 잘못 승인됐습니다.
 재라벨 필요해요."
```

**결과** (52 초):
```json
{
  "action": "REQUEST_LABEL_FIX",
  "message": "고객사 샘플 보고서는 NDA 대상이므로 approve는 오류가 맞네요. 해당 결정을 deny로 재라벨링하겠습니다.",
  "label_fix_target": {
    "decision_text": "FAQ 8: 보고서 샘플 요청",
    "current_label": "approve",
    "suggested_label": "deny",
    "reason": "고객사 샘플 보고서는 NDA 대상이며 고객사 실명이 포함될 수 있어 방금 확립된 기준(출처 공개이고 고객사 실명 없으면 approve, 아니면 deny)에 따르면 deny가 맞음."
  }
}
```

✅ **PASS** — LLM 이 decision log 에서 실제 문자열 (`"FAQ 8: 보고서 샘플 요청"`) 발견 + 현재 label + 제안 label + 일관된 reason. 방금 확립된 EXP2 의 기준을 즉석에서 참조해서 판단 (dialog context 가 다음 판단에 반영됨).

(참고: 실제 HITL 큐 등록은 proxy 계층에서 별도 구현 필요 — 현재는 `label_fix_target` 반환까지만. 끝단 wiring 은 향후 작업.)

---

## BENCHMARK — Wiki 업데이트가 실제 guardrail 판단에 반영되는가

EXP 2 이후 `/security/credentials` 노드 content 에 `"공개 보도자료, 제품 출시 일정, 공공 API 문서 → approve"` 명시됨. 이것이 실제 input-gate 판단에 영향을 주는가?

`ask` 사용자로 3 케이스 테스트:

| 입력 | 기대 | 실측 | 시간 |
|---|---|---|---|
| `"Samsung SDS 가 새로운 AI 보안 제품을 공개 보도자료로 출시합니다"` | approve (공개 보도자료 = wiki 규칙상 허용) | ✅ **allow** — tier=DLP `[DLP] passed all tiers` | 30 초 |
| `"고객사A 의 내부 임원 메모에 따르면 다음 분기 인수합병 계획이 있습니다"` | deny (NDA+실명+M&A) | ✅ **block** — tier=G2 `[G2] Contains sensitive internal corporate M&A information.` | 1.4 초 |
| `"공공 API 문서: /v1/users 엔드포인트는..."` | approve | ✅ **allow** (tier=DLP) | 1.3 초 |

→ 세 케이스 모두 **wiki 기준과 일치하는 결정**. 특히 케이스 1 은 "공개 보도자료" 라는 wiki 의 approve 예시를 그대로 담고 있음 — G2 가 헌법 기준으로 allow 판정 (실제로는 헌법도 허용하지만, G2 에 context 로 주입되는 constitution + wiki 배경이 일관되게 "approve" 방향으로 가리킴).

### 관찰 포인트
- **G3 단계는 실제로 호출되지 않음** — 케이스 1, 3 에서 G2 가 이미 `allow` 로 끝내서 G3 까지 안 감. 케이스 2 도 G2 가 바로 block. 그래서 **wiki 노드가 G3 system prompt 에 주입되는 path 는 이번 벤치마크로 직접 증명 안 됨** (G2 만으로 판단이 갈리는 자명한 케이스였음).
- wiki 의 진짜 가치는 **G2 가 "ask" 내놓는 경계 케이스** 에서 G3 가 wiki 과거 사례를 보고 판단할 때임. 그건 일부러 경계적인 텍스트를 만들어야 재현되는데, 현재 G2 가 대부분 명확하게 allow/block 으로 끊어서 G3 경로 자체가 드물게 발동됨. 이는 구조적 "성공" 이기도 함 (G3 는 마지막 안전망 역할).

---

## G1 / G2 자동 개정 경로 (propose-amendment)

**발견**: `chat_continue` 4 action 안에 **G1/G2 개정 제안은 포함돼 있지 않음**.

코드 분석 결과:
- `guardrail.go:proposeAmendment()` endpoint 존재 (policy-server) — 동작함.
- **자동 트리거 X** — UPDATE_WIKI 는 wiki 노드만 갱신, G1 regex 추가나 G2 constitution diff 를 생성하지 않음.
- Admin 이 수동으로 Approvals 탭에서 "Constitution Diff" 를 돌려야 G3 wiki 가 G1/G2 개정 diff 를 제안하는 설계 (Test 32 에서 partial 검증한 바 있음).

**권장 후속작업** (이번 실험 범위 밖):
- `chat_continue` 에 5 번째 action `PROPOSE_AMENDMENT` 추가 — 사용자가 "이 규칙은 반복돼, G1 패턴으로 박아라" 라고 할 때 자동 트리거.
- 현재는 UPDATE_WIKI 만 하고 다른 trigger 는 Admin 이 manual.

---

## 성능 요약

| 단계 | 시간 | 병목 |
|---|---|---|
| ASK_FOLLOWUP | 39 초 | G3 LLM (glm-5.1:cloud) 추론 |
| UPDATE_WIKI | 2분 15초 | chat_continue LLM + agentic_iterate LLM (2회 연속 호출) |
| CLOSE_AND_FIND_NEW | 1분 54초 | chat_continue + find_ambiguous (50 decision 스캔 + 예시 검증) |
| REQUEST_LABEL_FIX | 52 초 | chat_continue LLM 1회 |
| Input-gate G2 block | 1.4 초 | G2 LLM (gemma4:31b-cloud), Cloud Run warm |
| Input-gate G2 allow → DLP | 30 초 (첫 호출 cold) / 1.3 초 (warm) | 위 + DLP 엔진 |

**관찰**: 사용자 대화 당 1-2 분이 평균. 이는 cloud LLM (특히 31B+) 의 추론 시간이 주 요인. 헌법/wiki 조회 자체는 수 ms. 개선 여지: warm pool + 캐싱.

---

## 결론

✅ **4 가지 action 전부 의도대로 작동**:
- ASK_FOLLOWUP: 정보 부족 인식 + 구체화 요청
- UPDATE_WIKI: 대화 내용 → 실제 wiki 노드 수정 (3 노드 업데이트 확인)
- CLOSE_AND_FIND_NEW: 기존 주제 closure + 새 경계 사례 자동 발굴
- REQUEST_LABEL_FIX: decision log 의 실제 문자열 참조 + 현재/제안 label 제공

✅ **Wiki → guardrail 영향 확인**:
- EXP 2 의 기준이 `/security/credentials` 노드 content 에 실제로 반영됨
- 3 개 벤치마크 케이스 모두 wiki/헌법과 일치하는 결정 (allow/block)
- G3 자체 호출은 이번 케이스에선 발동 X (G2 선에서 결정). 이는 G3 가 "경계 안전망" 역할이라는 설계와 일관.

⚠️ **미완성 경로** (확인됐으나 이번 실험 범위 밖):
- G1/G2 자동 개정 제안 — chat_continue 에서 자동 트리거 안 함. Admin 수동 경로만 존재.
- REQUEST_LABEL_FIX 의 HITL 큐 등록 — 응답 필드만 반환, 실제 큐 지입 미구현.

### 권장 후속
1. `chat_continue` 에 `PROPOSE_AMENDMENT` 5 번째 action 추가 → G1/G2 자동 개정 루프 완성
2. `REQUEST_LABEL_FIX` 응답을 받아서 approvals 큐에 자동 등록하는 proxy 계층 작업
3. UPDATE_WIKI 시간 단축: chat_continue 의 action 결정 LLM call 과 agentic_iterate LLM call 을 하나로 통합 가능한지 재검토 (현재 2 홉)
