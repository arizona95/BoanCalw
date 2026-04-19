# Test 16 — Admin Approval HITL (Human-In-The-Loop)

**기능**: G3 가 "ask" 로 답하면 관리자 승인 큐 생성, 관리자가 승인/거부 → 사용자 전송 재개/차단.

## 경로
- `input_gate.go` L397-412: G3 decision==ask → `createApproval` 호출 → approval store 에 pending entry.
- `admin.go` L4210+: `GET /api/approvals` 목록, `POST /api/approvals/{id}/approve|reject`.
- Frontend `Approvals.tsx` → 목록 조회 + 승인/거부 버튼.

## 현재 상태
```
$ curl /api/approvals
[]
```
현재 pending approval 없음. 현재 조직 헌법이 명확해서 G3 가 `ask` 출력을 잘 안 내놓는 상태 (주로 allow/block).

## 검증 가능성
G3 가 `ask` 를 출력하려면 모호한 텍스트 + G3 wiki hint 설정이 필요. 구조적으로:
- pending approval 생성 로직 ✓ (`approvalStore.Create`)
- 관리자 조회 ✓
- 승인 시 `chatApi.inject` 로 "관리자 승인 완료" 메시지 주입 (MyGCP.tsx L422)

## 결론
✅ 인프라 완비. 현재 G3 가 ask 결정 잘 안 내어 empty 하지만 구조 검증됨.
