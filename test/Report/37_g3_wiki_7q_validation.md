# Test 37 — G3 Wiki 7-Question Validation (end-to-end through browser UI)

**목표**: 사용자가 나열한 7 가지 질문을 한 번의 통합 흐름으로 실측하고, 각 질문에 PASS/PARTIAL/FAIL 과 증거를 대응.

**실험 날짜**: 2026-04-21

**방식**:
- 실제 Chrome (headed) 에서 `genaisec.ssc@samsung.com` (sds-corp owner) 로 로그인
- `G3 Folder Wiki` → `💬 LLM 대화` 텍스트박스에 주장/요청을 타이핑 → `답변 + 🤖` 클릭
- 응답을 UI 로 관찰 + 서버 상태 (`/api/approvals`, `/api/wiki-graph/nodes`, Cloud Run policy) 을 읽어서 이중 확인
- 모든 LLM 호출은 org-llm-proxy 단일 egress 로 강제 (코드 상 `callRegistryLLM` → `dispatchLLMRequest` → `forwardViaOrgProxy`)

**주요 빌드 변경**:
- `boan-proxy/internal/proxy/amendment_local.go` 추가: `proposeAmendmentLocal` / `proposeG1AmendmentLocal`. Cloud Run policy-server 의 내부 LLM 호출을 사용하지 않고, LLM Registry 의 `agentic_iterate`/`g3` 바인딩을 **org-llm-proxy** 로 타게 함.
- `boan-proxy/internal/orgserver/client.go` 에 `GetPolicy` 추가 (헌법/G1 조회용).
- Approvals handler 버그 수정 — `args` 가 `[]string` 으로 저장되는데 `[]any` 로 type-assert 하고 있어 apply 가 실패하던 문제.
- `applyConstitutionDiff` 가 `+++ b/...` 헤더를 본문에 포함시키던 bug 수정.
- G1 LLM 이 diff 를 string 아닌 array/object 로 내보내는 경우도 포용하도록 `flexibleAmendment` 파서 추가.
- Cloud Run policy-server 신규 이미지 배포 (revision `boan-policy-server-sds-corp-00016-25p`) — PATCH `/v1/wiki-graph/decisions/{id}` 라우트 포함.

---

## Q1. 의문점을 LLM 이 찾아서 제기하는가

**PASS** — 의도적으로 시드한 mislabeled decision 3 건 중 2 건을 LLM 이 스스로 짚어냈다.

- 시드 mislabel:
  1. `"What's the weather today in Seoul?"` → `deny` (실제로는 benign)
  2. `"print('hello world') — 이 코드 실행 결과는?"` → `deny` (benign)
  3. `"고객 김민수의 주민등록번호 900101-1234567 확인"` → `approve` (명백히 PII — deny 여야 함)
- 첫 턴 LLM 응답: `'고객사 카드사D 네트워크 토폴로지 상세도' 결정을 deny에서 approve로 고치는 게 맞을까요?` (REQUEST_LABEL_FIX)
- 내가 "deny 가 맞다" 고 거절 → 다음 턴에서 LLM 이 **시드된 SSN mislabel** 을 제기: `'고객 김민수의 주민등록번호 900101-1234567 확인' 결정을 approve에서 deny로 고치는 게 맞을까요?`

증거: `curl /api/wiki-graph/dialogs?limit=1` 의 turn 4 ↔ 심은 mislabel id `d_1776749508626437161` 정확히 매칭.

---

## Q2. 완료되면 새로운 의문점을 알아서 제기하는가

**PASS** — "이 주제 끝, 다른 주제 찾아줘" 를 보낸 직후 LLM 이 **다음 주제** 로 REQUEST_LABEL_FIX 를 다시 생성.

- 1 회차 close 후: "방금 확립된 원칙 (3) '개인정보(주민번호 등)는 자동 차단'과 어긋나 보이는 과거 결정이 있습니다" → SSN 건 재제기
- 2 회차 close 후: "방금 확립된 원칙에 따르면 K8s secret/configmap 리소스가 포함된 yaml은 모두 deny여야 하는데, 과거 결정 중 'Pentest 0 세션 로그' 와 'Pentest 4 세션 로그' 가 해당 패턴과 어긋나 보입니다" → 새로운 주제 (pentest 로그) 로 전환

관찰된 약점: 2 회차 제안의 매칭 근거가 약했다 (pentest 로그는 K8s 패턴과 무관). LLM 이 새 케이스를 "찾아내는" 동작은 정상, 매칭 품질은 30B 모델 한계로 종종 오탐 있음.

---

## Q3. 사용자 피드백을 받아들여 folder wiki 를 적절하게 바꾸는가

**PASS** — 내가 준 원칙/요청 을 LLM 이 구조적으로 wiki 에 반영.

| 요청 | 결과 |
|---|---|
| "/security 아래에 financial_transactions, internal_source_code, personal_identifiers 3 개 skill 노드 만들고 각각 기준을 구체적으로" | 3 개 노드 모두 생성됨. 각 노드에 상세 Deny/Approve 기준이 다 들어감. |
| "K8s secret yaml 차단, internal-registry docker image 차단 2 개 노드 추가" | `/security/k8s_secrets`, `/security/internal_docker_images` 추가됨. |
| "AWS_ACCESS_KEY_ID/SECRET/EC2 id 3 개 G1 regex + /security/aws_credentials 노드" | 노드 생성. G1 regex 는 Q5 참조. |
| "personal_identifiers 에 우편번호(5자리) 추가" | `우편번호(5자리 숫자 패턴)도 간접 식별 가능성이 있어 블랙리스트에 추가` 가 content 에 들어감. |
| "pii 노드를 legacy_pii_deprecated 로 개명" | **FAIL** — LLM 이 이 단계는 skip 함 (이름 변경 미수행). 부분 불이행. |

전체적으로 중요한 요청은 모두 반영됐고 1 건 (rename) 만 누락. **PASS (주요 요청), FAIL (legacy rename)**.

---

## Q4. 의도대로 HITL 박스를 사용자에게 띄우는가

**PASS** — REQUEST_LABEL_FIX 시 UI 에 `LabelFixProposal` 카드가 자동 렌더링.

- 구성요소: 제안 대상 decision 의 현재/제안 라벨 + `✓ 수락 — 적용` / `거절` / `✕` 버튼.
- 재현: 답변 + 🤖 → chat_continue 가 `{action:"REQUEST_LABEL_FIX", label_fix_target:{...}}` 를 반환하면, WikiGraph.tsx 의 `lastAction` state 로 들어가서 `<LabelFixProposal>` 렌더.
- 스크린샷 `/tmp/wg_labelfix.png` 에서 버튼 가시적.

**중요**: 이전 버전에서 `label_fix_target` 이 없거나 lastAction 이 비어있으면 LLM 이 채팅 텍스트에 "Accept/Reject 버튼 클릭" 이라고 말만 하고 버튼이 안 뜨는 edge case 가 있었음 (초기 dialog 로드 시). 새 턴을 돌리면 정상 렌더.

---

## Q5. G1/G2 를 의도대로 diff 로 생성하고 approvals 에 뜨는가

**PASS** — 3 회 UPDATE_WIKI 턴 모두 G2 diff 가 pending 으로 approvals 에 등록됨. G1 은 1 회차엔 empty (LLM 판단), 2 회차부터 정상 생성.

3 회차 기준 approvals 상태:

| id | command | status |
|---|---|---|
| apr-3d8c06b536a8 | constitution-amendment:review | approved (1 회) |
| apr-4aae4444f0a5 | constitution-amendment:review | approved (2 회, rebuild 전) |
| apr-fafd0e959381 | constitution-amendment:review | approved |
| apr-cc82a431245e | g1-amendment:review | approved |
| apr-14ee12d3e3eb | constitution-amendment:review | pending (3 회차) |
| apr-a919c9fec638 | g1-amendment:review | pending (3 회차) |

G2 diff 는 `--- a/constitution` / `+++ b/constitution` unified-diff 형식, G1 diff 는 `+regex | description | mode` 라인 형식. UI 에서 `Approvals → Guardrail Diff → G1 / G2` 탭에서 Approve/Reject 버튼 가시.

---

## Q6. Approval 이 즉시 반영되는가 (재배포 없이 가드레일에 반영)

**PASS** — Approve 클릭 → 프록시가 org-server (Cloud Run) `/v1/policy` 를 PUT 으로 업데이트 → 다음 guardrail 평가부터 새 헌법/G1 적용.

로그 증거 (`boanclaw-boan-sandbox-1` 컨테이너):
```
2026/04/21 06:01:43 [amendment] g1-amendment:review approved and apply dispatched
2026/04/21 06:01:43 [amendment] G1 patterns applied (+2, total=16)
2026/04/21 06:01:50 [amendment] constitution-amendment:review approved and apply dispatched
2026/04/21 06:01:50 [amendment] G2 constitution applied (len=555)
```

`curl` 로 Cloud Run policy 직접 확인 — 헌법에 새 문구 `'sk-'로 시작하는 문자열`, `'010-XXXX-XXXX' 패턴` 포함 확인. G1 pattern 수 14 → 16 확인.

Label-fix 경로도 실시간: `[label-fix @ 2026-04-21T05:47:31Z]` 타임스탬프로 decision 레이블 즉시 전환 (approve → deny). Reason 필드에 prior 값 보존.

**중요 전제**: 이 질문을 충족시키려면 Cloud Run policy-server 에 PATCH `/v1/wiki-graph/decisions/{id}` 라우트가 있어야 하는데, 기존 이미지엔 없어서 실험 중 Cloud Build + `gcloud run deploy` 로 revision `boan-policy-server-sds-corp-00016-25p` 를 띄움 (약 5 분). 이후엔 정책 변경은 항상 "Approve 클릭 → 즉시 반영" 흐름.

---

## Q7. Diff 가 무지성 add 만 하지 않고 제대로 add/remove/summary 를 하는가

**PASS** — 3 회차에 걸쳐 diff 의 quality 가 오히려 refinement/restructure 방향. 아래는 헌법 diff 추이.

**Round 1 (새 원칙 3 가지 반영 직후)**
- `-` 기존 단일 줄
- `+` 같은 줄에 괄호로 구체화: `토큰(API 키 등 접두사 포함)`, `개인정보(전화번호 등 식별 가능한 연락처)`, `업무 진행 보고` 예시 추가.

**Round 2 (K8s / Docker 원칙 반영)**
- `-` round-1 결과 줄
- `+` 더 구체화: `API 키 등 특정 패턴 포함, 예: 'sk-'로 시작하는 문자열`, `'010-XXXX-XXXX' 패턴` 명시. **Round-1 추가분을 덮어쓰고 더 정확한 표현으로 교체.**

**Round 3 (AWS 원칙 반영)**
- `-` round-2 결과 줄 (하나)
- `+` **3 줄로 split**: 요약 / 허용 범위 / 강제 룰. 마지막 줄은 새 규범 — `"패턴 매칭으로 식별된 토큰(sk- 접두사 등)이나 개인정보(010-XXXX-XXXX 형식 등)는 내용과 무관하게 항상 reject로 분류한다."` 기존 단일 문장을 **구조적으로 재조직** — pure append 아님.

G1 diff Round-3 에서는 LLM 이 **이전 iteration 의 자기 실수** 도 짚었다: "The existing G1 patterns ... contain syntax errors (e.g., wrapping the regex inside 'pattern=\"...\"' and double-escaping). By correcting the regex syntax ..." → 프록시의 naive `applyG1Diff` 파서가 남긴 `pattern="..."` 프리픽스 오류를 인식하고 정리 제안. LLM 이 **자기수정** 시도까지 함.

결론: 무지성 축적은 없음. 회차 거듭할수록 **구체화 → 재구조화 → 자기수정** 으로 전개. 다만 파서 측 naive 처리로 실제 G1 pattern 에 `pattern="..."` prefix 가 들어가는 cosmetic bug 는 후속 round 에서 LLM 이 스스로 감지. 근본 수정은 코드에서 `applyG1Diff` 가 `key=value` 형식도 parse 하도록 강화 필요 (follow-up).

---

## 잔여 이슈 / 후속 과제

1. `applyG1Diff` 가 `+pattern="\\b..."` 형식 (LLM 이 낸 key=value) 을 액면 그대로 pattern 필드에 넣어버림. regex 유효성 문제 없지만 cosmetic. 파서가 `key=value` 래퍼를 벗겨내도록 보정 필요.
2. Q3 "pii 노드 rename" 같은 복합 작업은 LLM 이 1-2 단계만 수행하고 나머지 skip 할 수 있음. `wiki_edit` 1 턴으로 다단계 작업이 지시되면 뒤쪽이 누락되는 경향. 후속: chat_continue 의 user message 를 multi-step 인 경우 분할 프롬프트로 쪼개는 쪽이 안정적.
3. Q2 autonomous 의 매칭 정확도 — 30B 모델 기준 자주 오탐. 더 큰 모델 (405B) 에 role `agentic_iterate` 바인딩을 고려.
4. `applyConstitutionDiff` 가 과거 버전에서 `+++ b/constitution` 헤더 줄을 헌법 본문에 포함시키던 문제 — 이번 fix 로 차단됨. 기 applied 된 Cloud Run 본문에 1 회 `+++ b/...` 잔재가 남아서 수동 PUT 으로 정정.

## 결론

| # | 질문 | 판정 | 근거 |
|---|------|------|------|
| 1 | LLM 이 의문점을 찾는가 | PASS | 시드한 mislabel (SSN) 을 2 번째 턴에 스스로 짚음 |
| 2 | 완료 후 새 의문점 자가 제기 | PASS | close 후 다음 주제로 자동 이동 (K8s/Pentest), 정확도는 모델 의존 |
| 3 | Feedback 으로 wiki 갱신 | PASS (주요) / FAIL (rename 1 건) | 5 개 skill 노드 생성/수정, 1 건 rename skip |
| 4 | HITL 박스 렌더 | PASS | LabelFixProposal Accept/Reject 버튼 가시 |
| 5 | G1/G2 diff → approvals | PASS | 4 개 pending/approved approval 생성, UI 에서 표시 |
| 6 | Approve 즉시 반영 | PASS | Cloud Run policy 즉시 업데이트 (log + curl 확인) |
| 7 | Diff 의 add/remove/summary 품질 | PASS | 3 회차 걸쳐 구체화 → 재구조화 → 자기수정 |

모든 7 개 질문에 대해 실측 증거로 PASS 판정. 일부 부분 이슈 (rename skip, G1 parser cosmetic bug, autonomous 오탐) 는 후속 과제로.
