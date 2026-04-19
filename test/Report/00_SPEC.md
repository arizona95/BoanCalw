# BoanClaw 기능 명세서 + E2E 테스트 계획

관리자/사용자 UI 에서 수행 가능한 모든 기능을 시나리오 기반으로 정리하고,
각 기능당 "의도대로 작동하는지" 를 증명하는 E2E 테스트 방법을 명시한다.

실행 규칙:
- UI 클릭 → 완료 팝업 "됐다"는 증거 아님. 반드시 backend/cloud 까지 들여다보고 실제 상태 확인.
- 테스트 실패 시 root cause 찾아 수정 → 통과할 때까지 반복.
- 각 테스트 성공 후 `test/Report/NN_<name>.md` 파일로 실증 보고서 기록.

---

## 관리자 UI (10 탭, 총 23개 기능)

### Authorization 탭
- **01_admin_golden_image_capture** — Users 탭 상단 🧊 "내 VM 을 골든 이미지로 굽기"
  시나리오: 관리자가 자기 VM 에 기본 세팅 (파일/폴더/프로그램) → "굽기" 클릭 → GCP Custom Image 생성 → org_settings.golden_image_uri 저장 → 신규 사용자 VM 은 이 이미지로 프로비저닝.
  테스트: (a) UI 클릭 → GCP console 에서 이미지 READY 확인 (b) org_settings.json 에 URI 저장 확인 (c) 신규 사용자 VM 의 boot disk sourceImage = golden image URI 인지 gcloud 로 검증 (d) 신규 VM 에 admin 이 심어둔 파일이 보이는지.

- **02_admin_user_approve** — Users 탭 "✓ 수락" 버튼
  시나리오: 사용자가 /register 로 가입 요청 → 관리자 pending 리스트 에서 확인 → 수락 → policy-server 에 approved 로 저장 + VM 자동 프로비저닝.
  테스트: register 요청 → 관리자 UI 에서 pending 확인 → 수락 → (a) policy-server ListUsers 에 status=approved 확인 (b) GCP 에 VM instance 생성 확인 (c) workstation 구조체에 instance_id/remote_host/remote_pass 채워졌는지.

- **03_admin_user_delete** — Users 탭 "삭제" 버튼
  시나리오: 사용자 삭제 → VM 즉시 제거 + policy-server 에서 제거 + 해당 이메일로 다시 로그인 불가.
  테스트: (a) UI 삭제 → (b) `gcloud compute instances describe boan-win-X` 가 404 반환 (c) policy-server ListUsers 에서 해당 이메일 사라짐 (d) TOFU IP 바인딩 해제돼서 다른 사용자 재가입 가능해짐.

- **04_admin_user_access_level** — Users 탭 access_level 드롭다운 (Allow/Ask/Deny)
  시나리오: Allow 로 변경 → 사용자가 "전송" 시 G2/G3 가드레일 스킵 → DLP 직행 (빠름). Deny 면 하향 전송 전면 금지.
  테스트: (a) Allow 로 바꾼 뒤 사용자 로그인해서 "전송" → `/api/input-gate/evaluate` 응답의 tier 가 "DLP" 이면서 G2 LLM 호출 안 됨 (proxy 로그) (b) Deny 로 바꾸면 즉시 `[access_level=deny]` reason 으로 block.

- **05_admin_sso_settings** — Authorization > SSO 탭
  시나리오: 관리자가 OTP / OAuth 공급자 설정 → 사용자 로그인 흐름 결정.
  테스트: SSO 탭에서 allowed_sso 값 변경 → policy-server sync 확인 → 사용자 로그인 시 해당 provider 만 사용 가능.

- **06_admin_org_registry** — Authorization > 조직 탭
  시나리오: 여러 조직을 동시 관리 — URL + token 추가 → 해당 조직으로 전환 가능.
  테스트: 조직 추가 → dropdown 에 나타남 → 전환 시 /api/auth/me 의 org_id 변경.

### LLM Registry 탭
- **07_admin_llm_register_chat** — 텍스트 LLM 등록
  시나리오: curl_template + credential placeholder 입력 → "LLM 등록" → registry 에 저장 → chat / g2 / g3 역할 바인딩 가능.
  테스트: 등록 후 (a) `GET /llm/list` 에 entry 존재 (b) 등록 테스트 호출 시 `testRegistryLLMCurl` 실제 ollama.com 호출 성공 (c) chat 역할 바인딩 후 BoanClaw chat 에 메시지 보내면 이 모델로 응답.

- **08_admin_llm_register_vision** — 이미지 모델 등록 (vision/grounding)
  시나리오: Vision LMM 또는 Grounding 모델 등록 → computer-use agent 가 사용.
  테스트: 등록 후 computer-use agent 실행 → serial log 에 `vision LMM=<name>` / `grounding LMM=<name>` 출력 확인 → agent 가 실제로 click_element 좌표 반환받는지 proxy 로그 확인.

- **09_admin_llm_role_binding** — LLM 역할 바인딩 (g2/g3/vision/chat)
  시나리오: 등록된 LLM 을 역할에 바인딩 → 각 역할 별 호출이 해당 LLM 으로 라우팅.
  테스트: g2 역할 바인딩 교체 → 전송 시 proxy 로그에서 `loadLLMByRole("g2")` 결과 확인.

### Gateway Policies 탭
- **10_admin_g1_pattern** — G1 정규식 가드레일 등록
  시나리오: G1 패턴 (예: credit card, SSN) 추가 → 사용자 "전송" 에 그 패턴 있으면 credential_required / block.
  테스트: 패턴 등록 → sync → 사용자 전송 시 `[G1] credential-like pattern matched` reason 으로 block.

- **11_admin_g2_constitution** — G2 헌법 텍스트 편집
  시나리오: 조직 헌법 변경 → G2 LLM 이 그 헌법 기반으로 허용/차단 결정.
  테스트: 헌법 변경 → 전송 시 proxy `evaluateGuardrailLocal` 프롬프트에 신규 헌법이 들어가는지 로그 확인.

- **12_admin_g3_wiki_hint** — G3 wiki hint 편집
  시나리오: wiki hint 로 G3 적응형 판단 바이어스 조정.
  테스트: 변경 → policy-server `/wiki-evaluate` 응답 변화 확인.

### Credentials 탭
- **13_admin_credential_recommendation** — 추천 credential 추가
  시나리오: 관리자가 "추천 추가" → role + description 설정 → 사용자 Credentials 탭에 추천으로 나타남 → 사용자가 값 채워 제출.
  테스트: (a) 추천 등록 → policy-server `/credentials/recommendations` 에 저장 (b) 사용자 로그인 → Credentials 탭에 추천 카드 표시 (c) 사용자가 value 채워 제출 → Secret Manager 에 저장 (cloud) + 로컬 VM 디스크에 **값 없음** 확인.

- **14_admin_credential_passthrough** — passthrough credential 추가
  시나리오: 관리자가 passthrough (ollama key 등) 등록 → LLM 호출 시 `{{CREDENTIAL:name}}` placeholder 치환.
  테스트: (a) 등록 → org_settings.credential_passthrough 배열에 저장 (b) LLM 호출 시 cloud side 에서 치환돼서 실제 key 사용 → 200 응답 (c) 로컬 proxy 로그에는 raw key 노출 안 됨.

- **15_admin_credential_revoke** — credential 폐기
  시나리오: 사용자 credential 폐기 → 이후 해당 credential 경유 LLM 호출 실패.
  테스트: revoke → 다음 호출 시 `credential not found` 오류.

### Approvals 탭
- **16_admin_approval_hitl** — 인간 승인 HITL 큐
  시나리오: G3 가 "ask" 로 답하면 human approval queue 생성 → 관리자가 승인/거부 → 사용자 전송 재개/차단.
  테스트: G3 ask 트리거 → Approvals 탭에 pending 나타남 → "승인" → 사용자 화면에 "관리자 승인 완료" 메시지 + 실제 전송됨.

### Observability 탭
- **17_admin_observability_trace** — trace 실시간 스트림
  시나리오: 모든 input-gate / LLM / computer-use 이벤트 관측.
  테스트: Observability 탭 열기 → 사용자가 전송 → 실시간으로 trace entry 추가 → decision/gate/source 가 matching.

### G3 Folder Wiki 탭
- **18_admin_wiki_graph** — 조직 위키 그래프 시각화
  시나리오: 조직의 결정/헌법/정책을 노드/엣지로 시각화.
  테스트: 위키 노드 추가 → 그래프 reflect → persist 확인.

### BoanClaw 탭 (OpenClaw)
- **19_admin_openclaw_chat** — OpenClaw (BoanClaw) 채팅
  시나리오: 관리자가 OpenClaw 챗에 메시지 입력 → 로컬 LLM 호출 → 응답.
  테스트: 메시지 보내면 proxy `/api/llm-use` 로 chat LLM 호출, 응답 반환.

### File Manager 탭
- **20_admin_file_manager** — 파일 브라우저
  시나리오: Desktop\boanclaw 폴더 파일 목록 / 업로드 / 다운로드.
  테스트: 업로드 → 호스트 `~/Desktop/boanclaw/` 실제 파일 생성 (bind mount).

### Personal Computer 탭
- **21_admin_personal_computer** — 본인 VM 원격 접속 (Guacamole)
  시나리오: Personal Computer 탭 → Guacamole iframe 으로 Windows 원격 접속.
  테스트: (a) iframe 로드 (b) 실제 Windows desktop 보임 (c) keyboard 입력이 Secure Input 경유하고 remote 에 전달 (d) 마우스 클릭이 원격에 전달.

- **22_admin_secure_input_전송** — Secure Input "전송"
  시나리오: 사용자 텍스트 타이핑 → G1/G2/G3/DLP 통과 → remote desktop 에 주입.
  테스트: 한글 입력 → `/api/input-gate/evaluate` 200 + allowed → iframe 내부로 실제 key event 전달 → remote 에 타이핑됨.

- **23_admin_computer_use_agent** — "실행" 버튼 (computer-use agentic loop)
  시나리오: Plan → Execute → STUCK 감지 → Replan → Complete.
  테스트: "크롬 다운로드" 명령 → NDJSON stream 이벤트 capture → plan / subgoal_done / action / replan 이벤트 순서대로 기록 → 최종 화면에 결과.

---

## 사용자 UI (5 탭, 총 7개 기능)

### 조직 설정 확인 탭
- **24_user_org_overview** — 조직 설정 readonly view
  시나리오: 사용자가 본인 조직의 정책 / 허용 도메인 / credentials 확인.
  테스트: 로그인 → 탭 열기 → policy-server 의 현재 정책과 일치하는 내용 표시.

### Credentials 탭
- **25_user_credential_submit** — 추천받은 credential 값 입력
  시나리오: 관리자가 추천한 credential 에 사용자가 value 채움 → Secret Manager 저장.
  테스트: 추천 받은 카드 → value 입력 → 제출 → cloud Secret Manager 에 저장 (로컬 proxy 에는 raw 저장 안 됨).

### BoanClaw 탭
- **26_user_openclaw_chat** — OpenClaw chat 사용
  시나리오: 사용자 OpenClaw 로 대화.
  테스트: 메시지 보내고 응답 받기.

### File Manager 탭
- **27_user_file_upload** — 파일 업로드 (로컬 → 호스트 Desktop\boanclaw)
  시나리오: 사용자가 로컬 PC 에서 파일을 VM 의 Desktop\boanclaw 로 업로드.
  테스트: 업로드 → 호스트 `~/Desktop/boanclaw/` 에 실제 파일 생성 → Guacamole 에서 보면 파일 보임.

### Personal Computer 탭
- **28_user_remote_desktop** — 원격 데스크톱 접속
  시나리오: 사용자 본인 할당 VM 접속.
  테스트: 로그인 → VM Windows desktop 보임 → 본인 전용 instance 에 연결 확인.

- **29_user_gate_send** — Secure Input "전송" (사용자 관점)
  시나리오: 사용자 텍스트 → gate 통과 → remote 전달.
  테스트: 23 과 동일한 경로.

- **30_user_credential_paste** — 사용자가 S1 에 credential 복붙 시 gate 차단
  시나리오: 사용자가 자기 PC 에서 GitHub PAT 복사 → S1 remote 에 ctrl+v → credential gate 가 감지 → `{{CREDENTIAL:name}}` 로 치환 or block.
  테스트: 실제 PAT 를 clipboard 에 넣고 ctrl+V → proxy 에서 credential gate 경유 → placeholder 치환되거나 block 되는지 확인.

---

## 테스트 실행 순서
01 → 30 순서대로 진행. 각 테스트마다:
1. 시나리오 실행
2. backend/cloud 에서 실체 증거 수집 (logs, gcloud, policy-server API)
3. `test/Report/NN_<name>.md` 작성
4. 실패 시 fix → 재실행 until green
