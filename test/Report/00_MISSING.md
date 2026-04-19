# Test Coverage Gap 분석 — 35 개 리포트 이후 빠진 것

35 개 실증 리포트 + `scripts/test.sh` (Go unit + 5 bash 스크립트 + 16 integration) 를 다 훑었을 때 남은 공백입니다. 기능 명세서 (`00_SPEC.md`) 와 실제 코드(`admin.go` handlers, policy-server endpoints, UI pages) 를 대조한 결과.

---

## A. 이미 있는 테스트 (요약)

### Go unit
- `boan-proxy/internal/proxy/*_test.go` — input_gate, openclaw_provider 핵심 헬퍼
- `boan-proxy/internal/userstore/*_test.go` — 사용자 CRUD + 토큰
- `boan-proxy/internal/orgserver/*_test.go` — 조직 registry
- `boan-policy-server/internal/server/*_test.go` — policy store, guardrail eval

### Bash 스크립트 (scripts/test*.sh)
- **test-services** — 컨테이너 health
- **test-users** — 사용자 목록 / access_level / owner 보호
- **test-network** — network policy add/remove/rollback + 차단 호스트 curl
- **test-files** — S2/S1 list + S2→S1 안전/위험/폴더/경로탈출
- **test-credential-vault** — AES 키 격리 + 등록/조회/삭제
- **test-integration.sh (16 tests)** — 세션 발급 / sandbox-exec / openclaw 무결성 / network gate / G1 / file manager / audit trace

### 실증 리포트 (test/Report/ 01–35)
UI 탭 기능별 수동 E2E + backend/cloud 증거 포함.

---

## B. 🔴 완전히 빠진 영역 (자동화 없음, 리포트도 부분적)

### B-1. LLM Registry 자동화 (#07–09)
| 빠진 것 | 위치 | 왜 중요 |
|---|---|---|
| LLM 등록 (chat + curl_template) API CRUD 반복 | `POST /api/registry/llm` | 모든 가드레일이 여기 의존. 등록 깨지면 G2/G3 전부 실패 |
| Role binding 교체 (chat / vision / grounding / g2 / g3) | `POST /api/registry/llm/{name}/bind` | bind 잘못되면 사용자 메시지가 엉뚱한 모델로 라우팅 |
| 등록 해제 후 fail-closed 확인 | `DELETE /api/registry/llm/{name}` | security model 삭제 시 G2 가 fail-closed 로 block 하는지 |

### B-2. Guardrail Policy 편집 자동화 (#10–12)
| 빠진 것 | 확인할 것 |
|---|---|
| G1 정규식 add / mode 변경 (block ↔ credential ↔ redact) | `/api/policy/v1/policy` PUT → 다음 input-gate 호출에 반영되는지 |
| G2 헌법 텍스트 편집 | proxy `evaluateGuardrailLocal` 프롬프트에 새 헌법 들어가는지 |
| G3 wiki hint 편집 → evaluate 응답 변화 | `/wiki-evaluate` 요청/응답 diff |

### B-3. Credential full lifecycle 자동화 (#13–15)
test-credential-vault 는 로컬 파일 격리만 확인. 아래는 빠짐:
- **추천 생성 → 사용자 fulfill → Secret Manager 저장** 플로우 (cloud side)
- **Passthrough add → LLM 호출 시 substitute** (실제 outbound body 검사)
- **Revoke → 다음 호출 실패** (RPM / block 확인)

### B-4. Approvals (HITL) 자동화 (#16)
- G3 ask 트리거 → pending approval 생성
- Approve → 사용자 재시도 시 통과
- Deny → 사용자 재시도 실패
- Approval list pagination + filter

### B-5. Observability 자세한 검증 (#17)
`test_audit_traces_endpoint` 는 엔드포인트 200 만 확인. 빠진 것:
- 구체 이벤트(input-gate block, credential substitute, workstation provision) 가 전부 trace 에 들어가는지
- 필드 (user_email, org_id, tier, decision, reason) 완결성
- DELETE 시 clear 되는지

### B-6. Wiki Graph 자동화 (#18, 33, 34)
- 노드 CRUD: `POST/DELETE /api/wiki-graph/nodes`
- Agentic chat loop: `/api/wiki-graph/skill/chat_continue` — 4 action 순차 reach 되는지 (ASK_FOLLOWUP → UPDATE_WIKI → CLOSE_AND_FIND_NEW)
- wiki_edit 스킬 LLM 호출 → node 실제 업데이트

### B-7. OpenClaw chat forward (#19, 26)
- `/api/openclaw/v1/chat/completions` 에 메시지 → input-gate 통과 → chat LLM 호출 → 응답 스트림
- Allow / Ask / Deny 사용자별 다른 경로

### B-8. Personal Computer / Secure Input (#21, 22, 28, 29)
- `/api/input-gate/evaluate` mode=key / chord / paste / clipboard_sync 네 모드 다 테스트 (현재는 text 만)
- Guacamole iframe 상태 확인 (단위 테스트 불가하지만 WebSocket handshake 는 가능)

### B-9. Credential paste / clipboard (#30, 35)
Test 35 는 수동 리포트. 자동화된 것 없음:
- 등록된 credential 값 → placeholder 치환
- 미등록 raw key → redact + HITL
- passthrough 값 → 무조건 허용

### B-10. EDR / Wazuh (#31)
- Wazuh manager 포트 (1514/1515/55000) 열려있는지
- Fluent Bit 가 alerts.json 을 tail 해서 포워딩하는지 → stdout 로그 확인
- Windows agent install 스크립트 문법 검증 (PowerShell linter)

### B-11. Guardrail Diff / Amendment (#32)
- G3 training log 누적 → `/guardrail/propose-amendment` 호출
- Approval 수락 시 G1/G2 실제 반영
- **propose 경로는 policy-server 에 wiki LLM 필요** — 현재 Cloud Run 배포에 설정 안 됨 (문서에만 언급)

### B-12. Wiki LLM evolution (#33)
- 특정 사용자 의견 누적 → agentic_iterate → wiki 노드 drift 관측
- 장기 실행 테스트 (환경 한정)

### B-13. Golden Image 자동화 (#01)
- `/api/admin/workstation/image` POST → GCP Compute Images 생성
- 완료 후 org_settings.golden_image_uri 저장
- 다음 사용자 VM 이 해당 이미지로 provision
- **테스트 시간 3-5 분 / GCP 비용 발생** → 실행 조건 필요

### B-14. Org Registry + Multi-org (#06)
- `/api/admin/org/register` → 새 조직 추가 → dropdown 에 나타남
- 전환 시 `/api/auth/me` 가 새 org_id 반환
- 조직별 격리 (A 조직 사용자가 B 조직 정책 못 봄)

### B-15. SSO 설정 (#05)
- `/api/admin/settings/sso` → allowed_domains 변경
- 비허용 도메인 이메일로 가입 시도 → 거부

### B-16. User flow integration
전부 admin 관점. user 관점 자동화 부재:
- 사용자로 로그인 → credential submit → OpenClaw chat → 파일 업로드 → remote desktop 접속 까지 smoke path

### B-17. Bind user / TOFU IP
- 첫 로그인 시 IP 자동 캡처 (TOFU)
- 다른 IP 로 같은 계정 재로그인 시 차단

### B-18. Update / 버전 관리
- `update-watcher.sh` host-side 버전 체크
- 사이드바 "업데이트" 버튼 → `scripts/rebuild.sh` 트리거 → 재기동 후 새 버전 확인

### B-19. Workstation repair / delete 자동화
- `/api/workstation/repair` 호출 → VM boot 리셋
- 사용자 삭제 시 VM 실제 DELETE 되는지 (gcloud 확인)

### B-20. Device JWT / P3+P4 자동화
- 등록된 pubkey 없이 org-llm-proxy 호출 → 401
- Revoked device ID → 403
- Rate limit 초과 → 429
- policy-server 에도 device JWT middleware 추가됨 (이번 세션) → 검증 필요

### B-21. Cloud Run 서비스 직접 검증
- Cloud Run URL GET /healthz → 200
- Bearer 없이 POST /v1/forward → 401
- Invalid JWT → 401
- 3 서비스 모두 이런 direct tests 없음

---

## C. 🟡 부분 자동화 (확장 필요)

### C-1. Network Gate 깊이
`test-network` 는 add/remove + curl evil.example.com 만 확인. 확장 필요:
- Outbound method 필터 (GET 허용, POST 차단)
- 정확한 port 제한 (443 허용, 80 차단)
- DNS resolution gate (hostname allowlist)

### C-2. Input Gate 깊이
`test_input_gate_g1_*` 는 text mode 만. 확장:
- mode=key (safe key 허용, 위험 키 차단)
- mode=chord (safe chord 허용)
- mode=paste + clipboard_sync
- G2 트리거 (ask 사용자 + 애매한 텍스트)

### C-3. File Manager S1→S2
test-files 는 S2→S1 만. 빠진 것:
- S1→S2 는 면제 경로 (높→낮 아닌 낮→높) — 실제로 gate 없이 통과하는지 확인 필요

---

## D. 🟢 이미 충실한 영역 (추가 필요 없음)

- Sandbox 격리 (S2) — SB-01~10 거의 다 CV-1~CV-6 + openclaw 무결성으로 커버
- OpenClaw version pin + sha256 런타임 검증
- User access_level 전환 (Allow/Ask/Deny)

---

## E. 우선순위 권고

**즉시 자동화 필요** (regression 잡기 쉬운 것):
1. B-1 LLM Registry CRUD
2. B-2 G1 / G2 편집 → gate 반영
3. B-3 Credential lifecycle (추천→fulfill→resolve)
4. B-20 Device JWT (P3/P4 가 이미 production 인데 regression test 없음)
5. C-1, C-2 Gate 깊이

**수동 리포트로 충분** (실행 비용 / 환경 의존 큼):
- B-10 Wazuh (수동 실행 체크리스트)
- B-13 Golden Image (GCP 비용)
- B-17 TOFU (IP 환경 필요)

**차후**:
- B-4~8 나머지 기능 세부 — 이미 수동 리포트 01~35 로 커버된 것 중 자동화 여력 따라 확장
