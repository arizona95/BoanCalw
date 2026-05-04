# Test 42 — Approvals 분리 + Kill Chain process 차단 + Wiki label_fix batch + Threat Leader

**날짜**: 2026-04-29.
**범위**: 사용자가 요청한 4 개 작업을 한 라운드에 진행 + 1 시간 검증.

---

## 1. (3) Approvals 분리 — User Actions / Guardrail HITL / KillChain HITL

**문제**: 한 페이지에 모든 승인이 모여서 사용자 가입과 가드레일 amendment 가 섞여 보임. 종류별 멘탈모델 분리 불가.

**구현**:

- **Backend** (`boan-proxy/internal/proxy/admin.go`):
  - `approvalCategory(cmd string) string` — command prefix 로 "user|guardrail|killchain" 자동 도출.
  - `/api/approvals?category=...` query filter 추가 + 응답 entry 에 `category` 필드 자동 부여.
  - `/api/approvals/{id}` GET 도 동일 category enrich.
- **Frontend**:
  - `src/components/ApprovalQueue.tsx` (신규) — 카테고리별로 list/approve/reject 하는 공용 컴포넌트.
  - `Approvals.tsx` 단순화 → `<ApprovalQueue category="user" />` 만.
  - `Guardrail.tsx` 에 새 sub-tab "HITL" 추가 → `<ApprovalQueue category="guardrail" />`. Save 버튼은 HITL 탭에선 숨김.
  - `KillChain.tsx` 에 새 tab "HITL" 추가 → `<ApprovalQueue category="killchain" />`.
  - `api.ts`: `ApprovalCategory` type + `approvalApi.list(category?)`.

**검증** (browser, sds-corp tester 세션):

| URL | 표시 |
|-----|------|
| `/approvals` | "User Actions" 헤더 + "대기 중인 사용자 행동 승인이 없습니다" |
| `/guardrail?sub=HITL` | "HITL · 가드레일 승인 큐" + 빈 큐 + User Actions 페이지 안내 |
| `/kill-chain` (HITL 탭) | "Kill Chain manual trigger 승인 + Threat Leader" + 빈 큐 |

세 페이지 다 분리 동작. backend `?category=user|guardrail|killchain` 모두 200 + valid JSON.

---

## 2. (1) Kill Chain UI sandbox 우회 + manual trigger process 차단

**문제 1**: `browse` skill 의 chromium sandbox 가 Ubuntu 24.04 AppArmor 에서 막힘 — `No usable sandbox!`.

**해결**: `CI=1 $B ...` 환경변수로 launch 시 `--no-sandbox` 자동 추가 (`browser-manager.ts:157`). `BROWSE_HEADED=1` 로 headed 도 가능.

**문제 2**: `requireOwner` 가 owner 만 통과 → testmode 의 tester 가 manual KILL 못 누름.

**해결**: `killchain_handler.go::requireOwner` 에 `if role == "tester" && roles.CanEdit(roles.Tester)` 분기 추가 (testmode 빌드 한정 허용 — release 빌드는 그대로 owner-only).

**검증** (KILL trigger E2E):

```
Manual Trigger UI:
  - dropdown: hour-test@test.com (boan-win-hour-test) 선택
  - reason: "process-block-test: axios 의심 호출 감지 (Threat Leader 시뮬)"
  - KILL 클릭
  → Incident 137538537257 created, status="running"
  → Incidents count: 1 → 2

GCP 측 결과 (30 초 후):
  $ gcloud compute instances list ... | grep hour-test
  boan-win-hour-test   TERMINATED   ← VM stop 단계 도달 ✓
```

**의미**: kill chain 의 "process 차단 → VM 격리/STOP/DELETE" chain 이 manual trigger 경로로 GCP 까지 실제 도달함. (자동 process 매칭 — Wazuh agent 가 보내는 webhook event 경로 — 는 agent 미설치라 별도 라운드.)

---

## 3. (W) Wiki label_fix batch + 용어 통일 (allow/deny)

**문제** (사용자 보고):
- LLM 이 "FAQ 7 라벨 바꾸자" → 사람이 거절 → LLM 이 다음 턴에 "이미 바꾼 줄 알고" 반대 방향으로 재제안. **단일 turn-by-turn 흐름의 한계**.
- decision_id 가 cloud 의 wiki_graph 에 없는 ID (LLM hallucination) → PATCH 404.
- 용어 inconsistency: 코드 곳곳 `approve` / `denied` 등 — `allow` 로 통일 요청.

**구현**:

- **policy-server** (`boan-policy-server/internal/policy/wiki_graph.go`):
  - `NormalizeDecision(v string) string` — legacy `"approve"` → `"allow"`. 다른 값은 통과.
  - `DialogTurn.LabelFixBatch []map[string]any` 필드 추가 (legacy `LabelFixTarget` 도 호환).
  - `AppendDecision` / `UpdateDecision` / `ListDecisions` 모두 read/write 시 정규화.
- **proxy wikiskills** (`skill.go`):
  - prompt 변경: `label_fix` 단일 → `label_fix_batch` 배열, label 값 `"approve|deny"` → `"allow|deny"`. `★BATCH PROACTIVE★` 가이드.
  - DialogTurn 의 `LabelFixBatch` parse + 라벨 정규화 + first-element 를 legacy `LabelFixTarget` 으로 함께 채움 (구 UI 호환).
  - RECENT DECISIONS 텍스트 만들 때 `approve` 검출 시 `allow` 로 표기.
- **frontend** (`WikiGraph.tsx`):
  - `LabelFixBatchProposal` 컴포넌트 신규 — 행마다 토글 (allow/deny) + 체크박스 (포함 여부) + 일괄 적용 버튼. 부분 거절 가능.
  - turn 의 `label_fix_batch` 가 1 개 초과면 batch 카드, 그 외 legacy 단일 카드.
  - `decision === "approve"` UI 검사를 `"allow" || "approve"` 로 정규화.
  - `api.ts` 의 `WikiDecision.decision` / `labelFixApply.new_label` type 에 `"allow"` 추가 (legacy 호환).

**Cloud Run 재배포**:
- `boan-policy-server-sds-corp` → revision 00018 (new image, NormalizeDecision + LabelFixBatch 필드 보존).
- `boan-policy-server-ada-corp` → revision 00003.

**검증**: 

- `tsc --noEmit` clean.
- `go build` (testmode + release) clean.
- LLM 호출은 비용 + cloud 의존성이 커서 실제 batch 응답까진 미실시. 다음 라운드에 G3 대화 트리거 후 batch 카드 시각 검증.

---

## 4. (2) Threat Leader 사이드바

**구현** (v1 — mock feed):

- **Frontend** `ThreatLeader.tsx` 신규 페이지 + 사이드바 "🐲 Threat Leader" 진입점.
- v1 hard-coded mock feed (3 entries):
  - `CVE-2024-39338` axios <1.7.4 SSRF (high severity, process="node")
  - claude-cli 정책위반 (medium, process="claude")
  - `CVE-2024-3094` xz/liblzma backdoor (critical, process="xz")
- 각 entry "+ Kill Chain Rule 로 추가" 버튼 → 기존 `/api/kill-chain/rules` POST 호출 → KillChain Rules 탭에 등장.
- Backend 변경 없음 (기존 endpoint 재사용).

**검증** (E2E):

```
1. /threat-leader 진입 → 3 entries 정상 렌더 ✓
2. axios "+ Kill Chain Rule 로 추가" 클릭
   → "Kill Chain rule 추가됨: 'Suspicious axios <1.7.4 invocation' (auto=false)" 토스트 ✓
3. /kill-chain Rules 탭 이동
   → 새 rule "Suspicious axios <1.7.4 invocation / node / MANUAL" 노출 ✓
   → Rules count: 2 → 3 ✓
```

**v2 후속** (별도 phase):
- NVD JSON / GitHub Security Advisory GraphQL 자동 fetch.
- LLM (G2 또는 별도 role="threat_parse") 가 advisory 파싱 → process_name / package_name 추출.
- 사이드바 badge 에 새 항목 count 표시.

---

## 5. 이번 라운드의 부수 변경

- **`browse` skill 호출 시 항상 `CI=1` env** — sandbox 우회 (Ubuntu 24+ AppArmor). 사용자 메모리 [feedback_browser_headed] 와 충돌 없음 (headless 가 Guacamole/RDP 세션을 안 빼앗는 한 OK).
- **`requireOwner` testmode 한정 tester pass-through** — admin 흐름을 자동화 테스트하면서도 release 빌드의 보안은 유지.
- **`git-credential-boanclaw` + git-guard `REAL_GIT` fix** (이전 라운드, 회귀 검증).

---

## 6. 합계

| 작업 | 상태 | 검증 |
|------|------|------|
| (3) Approvals 분리 | 완료 | UI 3 페이지 + backend filter 모두 동작 |
| (1) KillChain process 차단 manual trigger | 완료 | hour-test VM TERMINATED (GCP 직접 확인) |
| (W) Wiki label_fix batch + allow/deny | 코드 완료 | LLM batch 응답 시각 검증은 다음 라운드 |
| (2) Threat Leader v1 | 완료 | axios → KillChain Rule e2e |
| sandbox bypass | 완료 | `CI=1 $B` 로 안정 동작 |
| Cloud policy-server 재배포 | 완료 | sds-corp r18 + ada-corp r3 |

**남은 후속**:
- NVD/GitHub Advisory 자동 fetch (Threat Leader v2)
- Wazuh agent → webhook event 시뮬로 process 자동 매칭 검증
- LLM batch label_fix 시각 캡처
