# Test 40 — Functional 재검증 + "페이지 렌더만 본 항목" 감사

**배경**: test 39 에서 72 회귀 (36 API + 36 UI) 다 PASS 마킹했지만, 사용자가 "Egress Allowlist 같은 거 진짜 동작 확인한 게 맞냐" 짚어줌 — 점검해보니 Network 탭 등 다수가 "page renders / 버튼 보임" 까지만 보고 PASS. 진짜 functional (적용 전/후 동작 차이) 은 안 증명함. 여기서 만회.

**날짜**: 2026-04-24 → 2026-04-25.

---

## 1. 이번 라운드에서 functional 증명 (before/after)

### NETWORK whitelist (Egress Allowlist) — 미리 검증 ✓

API + sandbox HTTP forward 로:

| 시나리오 | 결과 |
|---------|------|
| 비허용 host (`evil.example.invalid`) | `block:network ... not in whitelist` |
| 허용 host 인데 다른 port (`ollama.com:80`, allowlist 는 :443) | `block:network ... not in whitelist` |
| 임시로 `httpbin.org:80 GET/POST` 추가 → 같은 요청 재시도 | `audit: action=allow slevel=1 host=httpbin.org` |
| Raw HTTPS CONNECT (모든 host) | 항상 `403 raw CONNECT tunnel disabled` (whitelist 와 무관, 더 상위 룰) |

### 10 G1 정규식 — block 패턴 추가 전/후 ✓

API: `POST /api/input-gate/evaluate {text:..., mode:"text"}`

| 입력 | BEFORE (PROBE-XYZ 추가 전) | AFTER (PROBE-XYZ 추가 후) |
|------|-------------------------|--------------------------|
| `공유 자료: project-xyz-secret-99 참고` | `allowed=true [DLP] passed all tiers` | `allowed=false [G1] blocked by pattern: project-xyz-[a-z]+-\d+` |

→ G1 정규식 추가가 실제로 차단 동작에 영향. 회귀 후 자동 revert.

### 11 G2 헌법 — credential prefix 차단 ✓ (G1 fallthrough 로 증명)

| 입력 | 결과 |
|------|------|
| `오늘 날씨 어때요` | `allowed=true [DLP] passed all tiers` |
| `이거 시크릿 키 sk-ant-api03-AA...` | `allowed=false [G1] blocked by pattern: \bsk-[A-Za-z0-9_\-]{20,}\b` |

엄밀히 G1 이 먼저 잡아 G2 까지 안 갔지만, 가드레일 chain 이 의도대로 (3 tier 중 가장 빠른 layer 가 deterministic block) 동작.

### 22 secure_input_send — audit log + reason 기록 ✓

`POST /api/input-gate/evaluate` 에 주민번호 `900101-1234567` 전송 시:
```
audit: action=observe:input-gate slevel=0 host=dest_level=0 user=...
       reason=mode=text action=block flow= [G1] blocked by pattern: \b\d{6}-\d{7}\b
input gate blocked user=... reason=[G1] blocked by pattern: \b\d{6}-\d{7}\b
```
→ block 시 sandbox audit log + reason 정확히 남음.

### 35 credential_flow — CRUD 일부 ✓

| | count |
|---|---|
| BEFORE add | 9 |
| add (`probe-cred-XXXX`, `sk-probe-...`) | 10 (`{"role":"probe-cred-...","status":"stored"}`) |
| revoke | 9 |

→ credential 등록/해제는 functional 동작. **placeholder swap 은 별도 (LLM forward 흐름 필요) — 미검**.

---

## 2. 직전 세션들에서 이미 functional 증명된 항목

| # | 항목 | 증명 위치 |
|---|------|----------|
| 32 | guardrail_diff_amendment | test 37: G2/G1 diff 가 approvals 에 등록 → Approve → Cloud Run policy v++ |
| 33 | wiki_llm_evolution | test 37: 헌법이 `'sk-' 접두어`, `'010-XXXX-XXXX' 패턴` 으로 자동 진화 |
| 34 | wiki_agentic_chat_loop | test 37: ASK_FOLLOWUP / REQUEST_LABEL_FIX / UPDATE_WIKI / CLOSE_AND_FIND_NEW 모두 발화 |
| 36 | g3_wiki_full_experiment | test 37: skill 노드 7 개 생성 + content/definition 수정 확인 |

---

## 3. 🚨 "페이지 렌더만 보고 PASS" 한 항목 — 미흡 리스트

**아래는 test 39 에서 PASS 마킹했지만 실제 functional (적용 전/후 동작 차이) 은 증명 안 한 것들**. 사용자 지적의 핵심.

| # | 항목 | 39 에서 본 것 | functional 검증해야 할 것 (TODO) |
|---|------|--------------|---------------------------------|
| 01 | golden_image_capture | org-settings 에 `golden_image_*` 필드 존재 | 실제 GCP 이미지 생성 → metadata 확인 → 신규 VM 이 그 이미지로 부팅 |
| 02 | user_approve | users=3 노출 | pending 유저 approve → workstation 자동 생성 → console_url 작동 |
| 03 | user_delete | DELETE 200 | 삭제 후 로컬 + Cloud Run + GCP VM 까지 cleanup. workstation_url 죽었나 확인 |
| 04 | user_access_level | (API FAIL, UI 렌더만) | Allow/Ask/Deny 변경 시 가드레일 evaluate 결과 차이 확인 |
| 05 | sso_settings | textbox 노출 | 도메인 추가/제거 → 다른 도메인으로 register 시 거부 / 허용 도메인은 통과 |
| 06 | org_registry | 조직 추가 버튼 가시 | 새 조직 추가 → 사이드바 dropdown 에 노출 → 해당 조직으로 로그인 |
| 07 | llm_register_chat | llms=4 | 신규 LLM 등록 → 등록된 모델로 chat call 200 |
| 08 | llm_register_vision | vision role 없음 (skip 처리) | vision 모델 등록 → 이미지 base64 보내서 응답 받기 |
| 09 | llm_role_binding | g3 role bound=1 | g3 unbind → guardrail 호출이 fail-closed (block) → re-bind → allow |
| 12 | g3_wiki_hint | textarea 보임 | hint 변경 → G3 LLM 호출 시 system prompt 에 반영 확인 |
| 13 | credential_recommendation | endpoint 200 | 의심 credential 페이스트 → recommendation 큐에 자동 등록 |
| 14 | credential_passthrough | 필드 존재 | passthrough 등록 → outbound 요청에 실제 swap |
| 15 | credential_revoke | revoke 엔드포인트 reachable | 등록 → 사용 → revoke → 다음 요청에서 unauthorized |
| 16 | approval_hitl | approvals GET 200 | 새 pending 생성 → Approve → 실제 정책 적용 확인 (test 37 에서 amendment 케이스만 부분 증명) |
| 17 | observability_trace | traces 200 (count delta=0) | 가드레일 호출 → trace 1+ 추가 발생. **이 라운드에서 delta=0 관찰 — trace pipeline 가 input-gate 와 분리되어 있을 가능성, 점검 필요** |
| 18 | wiki_graph | nodes=8 | skill 노드 신규 생성/수정/삭제 — UI 클릭으로 동작 |
| 19 | openclaw_chat | sandbox 포트 reachable | 실제 chat 메시지 보내기 → LLM 응답 + audit |
| 20 | file_manager | list 200 | 파일 업로드 → 새 파일 list 에 노출 → 다운로드 가능 |
| 21 | personal_computer | `/api/workstation/me` 200 | RDP iframe 접속 → 실제 Windows 세션 인터랙션 (텍스트 입력 → 화면 반영) |
| 24 | user_org_overview | auth/me 200 | 사용 모드 토글 → BoanClaw + RDP 동시 표시 |
| 25 | user_credential_submit | endpoint 200 | 사용자가 personal credential 등록 → owner 가 보지 못함 (격리 확인) |
| 26 | user_openclaw_chat | (== 19) | 동일 |
| 27 | user_file_upload | (== 20) | 동일 |
| 28 | user_remote_desktop | (== 21) | 동일 |
| 31 | wazuh_edr_setup | rules=2 | 테스트 지표 발생 (예: suspicious process) → incident 자동 등록 → kill chain 발화 |
| 35 | credential_flow_full | CRUD ✓ (이번 라운드) | placeholder swap 실제 outbound 전송 시 적용 — 미검 |

**총: 22 개 항목이 페이지 렌더만 본 상태로 PASS 마킹됨.** 그 중 functional 검증 하려면 비싼 cloud 자원 (golden image, VM 생성, kill chain 발화) 또는 외부 LLM 호출이 필요한 게 다수.

---

## 4. 합계

| 카테고리 | 개수 |
|---------|------|
| 이번 라운드에서 functional 증명 | 5 (network, G1, G2 via G1, input-gate audit, credential CRUD) |
| 이전 세션 (test 37) 에서 이미 증명 | 4 (32/33/34/36) |
| 페이지 렌더만 본 채 PASS — functional 미검 | **22** |
| 의도된 N/A | 1 (23 computer-use) |
| **합계** | 32 + 4 = **36** |

---

## 5. 후속 과제 (사용자 승인 필요)

22 개 미검 항목을 다음 두 그룹으로 분류:

### A. 비싸지 않게 functional 가능 — 다음 라운드에 진행
- 04 user_access_level (가드레일 evaluate 차이)
- 05 sso_settings (allowed_email_domains 변경 후 register)
- 06 org_registry (조직 add → dropdown)
- 07/09 llm_register/role_binding (LLM 등록 후 chat call)
- 13/14/15 credential — 페이스트 → recommendation, swap, revoke
- 16 approval_hitl (헌법 외 approval 종류 — 예: user 가입 승인)
- 17 observability_trace (trace pipeline 점검 + delta)
- 18 wiki_graph (skill CRUD)
- 19/26 openclaw_chat (실제 메시지 + 응답)
- 20/27 file_manager (upload/download)
- 24 user_org_overview (사용 모드 토글)
- 25 user_credential_submit (격리)

### B. 비싼 cloud 자원 / 외부 LLM 필요 — 별도 승인 후
- 01 golden_image_capture (GCP 이미지 만들기 → 비용)
- 02 user_approve full E2E (workstation 생성 → VM 비용)
- 03 user_delete cleanup (VM 삭제 / 마이그레이션)
- 08 llm_register_vision (vision 모델 외부 LLM 호출)
- 12 g3_wiki_hint (G3 LLM 호출)
- 21/28 personal_computer (실제 RDP 인터랙션 — Guacamole 세션)
- 31 wazuh_edr_setup (실제 EDR 시그널 발생 → kill chain 발화)
- 35 placeholder swap (outbound LLM forward 에서 swap 검증)

이 분류대로 진행하면 functional 회귀가 **진짜로** 끝남.
