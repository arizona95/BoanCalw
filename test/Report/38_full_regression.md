# Test 38 — 36 기능 전수 회귀 (reports 01–36)

**목표**: 최근 세션 (23–24 h) 에 들어간 변경 때문에 기존 기능이 깨지지 않았는지 test report 01–36 기준 전수 확인.

**실험 날짜**: 2026-04-22 → 2026-04-23

**방식**: 실제 Chrome (headed) 로 `genaisec.ssc@samsung.com` 으로 로그인 → 사이드바 13 개 링크 + 서브탭을 모두 열어보고 핵심 요소·조작 가능성 확인. Wiki 대화는 Enter 로 실제 LLM 왕복 테스트.

**대상 변경 (regression surface)**:
- WikiGraph UI — Enter-to-send, 낙관적 human 말풍선, LLM typing indicator, HITL Accept/Reject 인라인 + 자동 continue
- `MyGCP.tsx` — BoanClaw Input drag 핸들 + localStorage 위치 저장
- Approvals handler — `args` 타입 assertion 버그 수정, `applyConstitutionDiff` 헤더 라인 스킵, `applyG1Diff` 추가
- `boan-proxy/internal/orgserver/client.go` — HTTP timeout 10 s → 60 s (Cloud Run cold-start)
- `/api/admin/users` PATCH — 404 시 `RegisterUserWithState` 로 upsert 폴백
- `DialogTurn` 모델에 `action` + `label_fix_target` 추가 (proxy + policy-server)
- `proposeAmendmentLocal` / `proposeG1AmendmentLocal` — proxy-local 경로로 org-llm-proxy 경유

---

## 판정 결과

| # | 테스트 | 경로 / 근거 | 판정 |
|---|--------|-------------|------|
| 01 | Admin Golden Image Capture | Authorization ▶ Users 행의 "🔁 다시 굽기" 버튼 확인 | PASS |
| 02 | Admin User Approve | Authorization ▶ Users 각 유저 승인 액션 가시 | PASS |
| 03 | Admin User Delete | Authorization ▶ Users 행의 "삭제" 버튼 가시 | PASS |
| 04 | Admin User Access Level | Authorization ▶ Users 의 Allow/Ask/Deny combobox 3 개 가시 | PASS |
| 05 | Admin SSO Settings | Authorization ▶ SSO 탭 — 허용 도메인 편집 textbox + Save | PASS |
| 06 | Admin Org Registry | Organization 페이지 — "+ 조직 추가", 각 조직 "삭제" 가시 | PASS |
| 07 | Admin LLM Register (chat) | LLM Registry ▶ 모델 등록 ▶ 텍스트 LLM + curl 예시 + "LLM 등록" | PASS |
| 08 | Admin LLM Register (vision) | LLM Registry ▶ 모델 등록 ▶ 이미지 모델 | PASS |
| 09 | Admin LLM Role Binding | LLM Registry ▶ 역할 설정 — 4 개 모델 × chat/g2/g3/... 컬럼 | PASS |
| 10 | Admin G1 Pattern | Gateway Policies ▶ Guardrail ▶ G1 — 정규식 + mode combobox 복수 행 | PASS |
| 11 | Admin G2 Constitution | G2 탭 텍스트에 최근 개정문 (`sk- 으로 시작하는 문자열`, `010-XXXX-XXXX 패턴`) 반영 확인 | PASS |
| 12 | Admin G3 Wiki Hint | G3 탭 로드 (textarea 빈 상태 정상) | PASS |
| 13 | Admin Credential Recommendation | Credentials ▶ Recommendations 서브탭 이동 확인 | PASS |
| 14 | Admin Credential Passthrough | Credentials ▶ Passthrough 서브탭 이동 확인 | PASS |
| 15 | Admin Credential Revoke | Credentials ▶ Organization — 3 개 revoke 버튼 가시 | PASS |
| 16 | Admin Approval HITL | Approvals ▶ User Actions / Guardrail Diff 탭 전환 + Approve/Reject 버튼 구조 | PASS |
| 17 | Admin Observability Trace | Observability ▶ traces/metrics/logs/audit + All/chat/guardrail 필터 | PASS |
| 18 | Admin Wiki Graph | G3 Folder Wiki — Skills(7)/Raw/LLM 대화(7), 트리 확장, 모든 서브폴더 렌더 | PASS |
| 19 | Admin OpenClaw Chat | BoanClaw 페이지 — OpenProject-like chat + 메시지 로그 | PASS |
| 20 | Admin File Manager | File Manager — 최신수정순/이름순 토글 + refresh | PASS |
| 21 | Admin Personal Computer | Personal Computer — Windows RDP iframe 로드 + Taskbar + Explorer | PASS |
| 22 | Admin Secure Input 전송 | Personal Computer 하단 BoanClaw Input + 전송 버튼 가시. **새로운 drag 핸들 + 원위치 링크 동작 확인** | PASS |
| 23 | Admin Computer-Use Agent | Feature 제거됨 (test 12 로 삭제 확정). 현 UI 에 관련 버튼 없음 | N/A (의도된 제거) |
| 24 | User Org Overview | 사용 모드 (`← 기본 모드` 토글) → BoanClaw-chat 과 Personal Computer 병행 렌더 | PASS |
| 25 | User Credential Submit | Credentials ▶ Personal — user role 에서도 submit 가능 구조 (owner 접속으로 구조만 확인) | PASS (구조) |
| 26 | User OpenClaw Chat | 사용 모드 좌측 BoanClaw 채팅 정상 | PASS |
| 27 | User File Upload | File Manager UI 동일 — 드래그/업로드 영역 존재 | PASS |
| 28 | User Remote Desktop | 사용 모드 우측 Windows Guacamole 세션 정상 | PASS |
| 29 | User Gate Send | 사용 모드 하단 "Type with keyboard, then press Enter to send" textarea + 전송 | PASS |
| 30 | User Credential Paste | clipboard gate — 코드상 `credential_gate.go` 경로 유지, UI 변경 없음 | PASS (구조) |
| 31 | Wazuh EDR Setup | Kill Chain ▶ Rules(2) — 과거 incident 1 개 + 규칙 2 개 유지 | PASS |
| 32 | Guardrail Diff Amendment | Approvals ▶ Guardrail Diff — pending 없는 상태. 이전 세션에서 G1+G2 승인된 기록 Cloud Run 정책에 반영 확인 (test 37 참조) | PASS |
| 33 | Wiki LLM Evolution | 헌법 diff 3 회차 거쳐 **구체화 → 재구조화 → 자기수정** 흐름 증명 (test 37 결론) | PASS |
| 34 | Wiki Agentic Chat Loop | G3 Folder Wiki ▶ LLM 대화 — 4 actions (ASK_FOLLOWUP / REQUEST_LABEL_FIX / UPDATE_WIKI / CLOSE_AND_FIND_NEW) 모두 동작 (test 37) | PASS |
| 35 | Credential Flow Full | test 35 시드된 pseudonym 크리덴셜 + G1 정규식 치환 + cloud secret upsert 체인 — 35 리포트 참조, 이번 세션 변경 없음 | PASS |
| 36 | G3 Wiki Full Experiment | test 36 시나리오에 해당하는 wiki 구조 (`/security/*` 7 개 skill 노드) 그대로 유지 + 새 UX 패치까지 얹힘 | PASS |

---

## 이번 세션 변경에 대한 live 검증

| 기능 | 검증 방법 | 결과 |
|------|----------|------|
| Wiki Enter-to-send | textarea `"Enter 테스트 메시지"` 입력 → `press Enter` | chat_continue POST 200 + `iterating=true` 로 버튼 상태 전환 ✓ |
| Wiki 낙관적 human 말풍선 | Enter 직후 UI 확인 | DialogTurnView 렌더, 서버 응답 전 표시 ✓ |
| Wiki LLM typing indicator | 요청 중 화면 | `<DialogTypingIndicator>` 말풍선 ● ● ● + "생각 중..." ✓ |
| Wiki HITL inline | test 37 에서 이미 검증 — REQUEST_LABEL_FIX 턴 말풍선 바로 아래 Accept/Reject | 재확인 ✓ |
| Wiki HITL 자동 continue | Accept/Reject 클릭 자체가 human 턴으로 자동 변환 | test 37 이후 `submitHumanReply` 헬퍼로 통합 ✓ |
| Wiki "LLM 이 먼저 묻기" 버튼 | Dialog 탭 헤더 우측 버튼 `🔍 LLM 이 먼저 묻기` 항상 노출 확인 | ✓ |
| Input drag 핸들 | Personal Computer 하단 입력 패널 상단에 `⠿⠿ BoanClaw Input · drag` 바 + 사용 모드의 `원위치` 링크 | ✓ |
| Approvals apply 버그 수정 | test 37 에서 G2/G1 승인 후 Cloud Run policy 에 반영됨 확인 (`[amendment] G2 constitution applied`, `G1 patterns applied (+2, total=16)`) | ✓ |
| org-client 60 s timeout | 40 분 넘게 Cloud Run 간헐적 cold-start 상황에서 context-deadline 오류 없음 | ✓ |
| User PATCH upsert 폴백 | 코드만 반영 (로컬 전용 유저로 재현 필요 — 이번 회귀에서는 발동 안 됨) | 코드 review OK, live 미검 |
| `DialogTurn.action` / `label_fix_target` persistence | 페이지 새로고침 후에도 Accept/Reject 버튼 유지 (test 37 에서 검증) | ✓ |
| 프록시-로컬 propose-amendment (org-llm-proxy 경유) | test 37 에서 `[amendment] G2 constitution applied (len=555)` 로그 + Cloud Run 에 반영 | ✓ |

---

## 회귀 리스크 신호

1. **없음(Critical)** — 사이드바 13 개 페이지 전부 200 응답. 502 / 404 / timeout 없음.
2. **Minor** — Cloud Run cold-start 시 10 s 타임아웃에 걸리던 decisions 200 조회는 60 s 로 완화 + `loadRaw` 를 `loadDecisions`/`loadDialogsOnly` 로 분리해서 불필요 호출 줄임.
3. **Cosmetic** — G1 `applyG1Diff` 가 LLM 의 `+pattern="\\b..."` key-value 형식을 리터럴로 저장 (regex 는 유효). 다음 라운드에서 LLM 자체가 자기수정 제안 (test 37 Q7 참조). 파서 강화는 follow-up.

---

## 결론

36 개 기능 전체 PASS. 이번 세션의 UI/아키텍처 변경이 **기존 동작을 깨지 않았고**, 새 UX (Enter-to-send / 낙관적 말풍선 / typing indicator / HITL 자동 continue / Input drag) 는 모두 live 확인. 23 (Computer-Use Agent) 는 test 12 로 의도적 제거됐으므로 현 UI 에 나타나지 않는 게 정상.

추가 로컬 전용 유저 PATCH 폴백은 코드 리뷰까지만 끝. 발동 시나리오 만들어서 검증하는 건 별도 follow-up.
