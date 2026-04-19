# Test 32 — Guardrail Diff (G3 Wiki 자동 개정 제안) ⚠️ 부분 검증

**기능**: Approvals > Guardrail Diff 탭. G3 wiki LLM 이 축적된 decision history 를 바탕으로 G1 정규식 / G2 헌법 개정안을 자동 생성 → 관리자 diff 승인 큐 → approve 하면 실제 정책 반영.

---

## 시나리오
1. G3 wiki 가 학습한 판단 이력 기반 → 관리자가 "제안 생성" (또는 주기적 스케줄) → policy-server wiki LLM 호출 → 헌법/G1 diff 생성.
2. Approval 큐에 `constitution-amendment:review` 또는 `g1-amendment:review` cmd 로 등록.
3. 관리자가 Approvals 탭 > Guardrail Diff 로 들어가서 diff 확인.
4. Approve → backend 가 diff apply → policy-server PUT → 즉시 반영.

---

## 증거 — 경로별 검증

### ✅ 1) UI / API 엔드포인트 코드 경로 존재
- `admin.go` L2830 `/api/admin/propose-amendment` (G2)
- `admin.go` L2866 `/api/admin/propose-g1-amendment` (G1)
- `admin.go` L4350 approve 시 `cmd == "constitution-amendment:review"` 분기 → `applyConstitutionDiff` → `s.orgs.ClientFor(orgID).UpdatePolicy(orgID, ...)` 호출.
- `Approvals.tsx` L43-90 Guardrail Diff 서브탭 (G1/G2 필터).

### ❌ 2) 실제 propose 호출 — wiki LLM 미구성으로 502
```
$ curl -b owner.txt -X POST /api/admin/propose-amendment
{"error":"propose-amendment returned 502: wiki LLM not configured for amendment proposals"}
HTTP 502

$ curl -b owner.txt -X POST /api/admin/propose-g1-amendment
{"error":"propose-g1-amendment returned 502: wiki LLM not configured for G1 amendment proposals"}
HTTP 502
```
→ policy-server 쪽에 wiki LLM endpoint 가 설정돼있지 않음. 현재 환경에서 **자동 제안 생성 불가**.

### ✅ 3) Apply path — policy-server PUT 은 정상 동작
Amendment approve 시 수행되는 것과 동일한 PUT 호출 직접 테스트:
```
$ curl -X PUT .../v1/policy -d '{"guardrail":{"constitution":"TEST AMENDMENT ..."}}'
{"version":8}   HTTP 201

$ curl .../v1/policy | jq '.guardrail.constitution'
"TEST AMENDMENT APPLIED: 자격증명 외부 유출 금지 + 추가 조항 XYZ"
```
→ 정책서버 PUT → 즉시 반영 + 버전 bump. (테스트 후 원래대로 복구: version 9)

---

## 솔직한 결론

**부분 검증** — 두 개의 경로로 나눠서 평가:

| 경로 | 상태 | 증거 |
|---|---|---|
| Propose (wiki LLM → diff 생성) | ❌ 현재 환경 미검증 | 502 (wiki LLM 미구성) |
| Approve → Apply (diff → policy 반영) | ✅ 검증됨 | PUT 201 + 버전 bump + GET 반영 확인 |

**실 환경 E2E 완성을 위해 필요한 것**:
1. policy-server 환경변수 `BOAN_WIKI_LLM_URL` / model 설정
2. wiki LLM 에 "이전 결정 이력 → G1 정규식 추가 제안" 프롬프트 구성
3. propose 호출 → approval 큐 생성 → UI 렌더 → approve → PUT → reflected 전체 흐름 재검증

**이전 Test 16 (HITL) 과의 구분**:
- Test 16: 사용자 실시간 전송에 G3 가 `ask` 응답 → 관리자가 단발 승인/거부
- Test 32 (이것): G3 wiki 가 **정책 자체의 개정안**을 제안 → 관리자가 정책 자체를 업그레이드

두 기능 모두 Approvals 탭에 노출되지만 동작 계층이 다름.
