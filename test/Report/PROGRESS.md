# Test Progress — 전체 완료 ✅

30/30 완료.

| # | 기능 | 상태 |
|---|---|---|
| 01 | Admin Golden Image Capture | ✅ |
| 02 | Admin User Approve | ✅ |
| 03 | Admin User Delete | ✅ |
| 04 | Admin User Access Level (Allow/Ask/Deny) | ✅ |
| 05 | Admin SSO Settings | ✅ |
| 06 | Admin Org Registry | ✅ |
| 07 | Admin LLM Register (chat) | ✅ |
| 08 | Admin LLM Register (vision/grounding) | ✅ |
| 09 | Admin LLM Role Binding | ✅ |
| 10 | Admin G1 Pattern | ✅ |
| 11 | Admin G2 Constitution | ✅ |
| 12 | Admin G3 Wiki Hint | ✅ |
| 13 | Admin Credential Recommendation | ✅ |
| 14 | Admin Credential Passthrough | ✅ |
| 15 | Admin Credential Revoke | ✅ |
| 16 | Admin Approval HITL | ✅ |
| 17 | Admin Observability Trace | ✅ |
| 18 | Admin Wiki Graph | ✅ |
| 19 | Admin OpenClaw Chat | ✅ |
| 20 | Admin File Manager | ✅ |
| 21 | Admin Personal Computer (Guacamole) | ✅ |
| 22 | Admin Secure Input 전송 | ✅ |
| 23 | Admin Computer-Use Agent | ✅ |
| 24 | User Org Overview | ✅ |
| 25 | User Credential Submit | ✅ |
| 26 | User OpenClaw Chat | ✅ |
| 27 | User File Upload | ✅ |
| 28 | User Remote Desktop | ✅ |
| 29 | User Gate Send | ✅ |
| 30 | User Credential Paste (Clipboard Gate) | ✅ |

## 이번 테스트 sequence 에서 발견 + fix 된 버그 모음
1. `machine_id` 필드가 UI 바인딩 PC 컬럼에 안 나옴 → admin.go overlay 에서 machine_id → RegisteredIP fallback
2. startup script 에 Remote Desktop Users 그룹 누락 → group 추가 + NLA disable + `C:\ProgramData\boanclaw-startup.log` debug log
3. G2 JSON 파싱 실패 (CoT + tokenizer artifact) → `format:"json"` 강제 + `extractFirstJSONObject` brace walker
4. Agent click_element 미사용 → 프롬프트 강화 + server-side reject
5. Desktop icon double-click 규칙 → vision 프롬프트에 Windows UX 힌트
6. `looksBroken()` false positive ("Sign in" 문구) → Windows lock 특유 표현만 매칭
7. Fuzzy dedup 오차단 → screenChanged 체크 + subgoal 전이 시 cluster 리셋

## 보고서 위치
`test/Report/NN_<name>.md` — 각 기능별 시나리오 + 증거 + 결론.
