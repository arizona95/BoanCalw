# BoanClaw vs 타 Claw 보안 비교

## 아키텍처 비교

| 항목 | OpenClaw (원본) | open-computer-use | BoanClaw |
|------|----------------|-------------------|----------|
| 실행 환경 | 로컬 프로세스 | E2B 클라우드 샌드박스 | Docker 격리 + GCP RDP |
| 네트워크 제어 | 없음 | 없음 | fail-closed 화이트리스트 |
| 자격증명 관리 | 환경변수 노출 | 환경변수 노출 | AES 암호화 + 플레이스홀더 (S4 격리) |
| 정보 흐름 제어 | 없음 | 없음 | S4 영역 분리 + 3-Gate |
| LLM 가드레일 | 없음 | 없음 | 3-Tier 헌법→wiki→인간 |
| 정책 서버 | 없음 | 없음 | ed25519 서명 + 버전관리 |
| 감사 로그 | 없음 | 없음 | 전 이벤트 CSP 전송 |
| **Supply-chain 무결성** | `npm install -g openclaw@latest` (unpinned) | 동일 (unpinned) | **버전 핀 + sha256 빌드/런타임 양쪽 검증, fail-closed** |
| 호스트 권한 정합성 | 무관 | 무관 | sandbox UID = host UID (sudo 불필요) |

## OpenClaw에서 흡수한 것

**OpenClaw 플러그인 아키텍처**
- BoanClaw는 OpenClaw를 포크하지 않고 **플러그인으로 래핑**
- `boan-agent`가 OpenClaw의 tool system에 16+ 보안 도구 등록
- OpenClaw의 대화형 AI 에이전트 기능을 그대로 활용하면서 보안 계층만 추가

**흡수한 장점:**
- 도구 기반 확장성 (tool registration)
- 대화형 코드 실행 환경
- 플러그인 생태계 호환성

**BoanClaw가 추가한 것:**
- Git Guard: 위험한 git 명령 차단 (reset --hard, push --force, rebase -i 등)
- SSRF 방어: 사설 IP, 메타데이터 서버 접근 차단 (`safeFetch()`)
- Credential 필터링: LLM 응답에서 자격증명 자동 마스킹

## open-computer-use에서 흡수한 것

**SandboxAgent 도구 세트**
- `screenshot()`, `left_click()`, `double_click()`, `right_click()`, `scroll()`, `write()`, `press()`, `click_element()` 전체 포팅
- OS-Atlas 기반 OCR 그라운딩 (`click_query`)
- 타이핑 패턴 보존 (`TYPING_GROUP_SIZE=50`, `TYPING_DELAY_MS=12`)

**흡수한 장점:**
- Vision LLM 기반 화면 인식 + 액션 결정 루프
- Playwright 기반 브라우저 자동화
- 스크린샷 → 분석 → 행동 → 검증 (플립북 패턴)

**BoanClaw가 변경한 것:**
- E2B Desktop Sandbox → **Guacamole/RDP** 백엔드 (GCP Windows 작업 PC)
- 직접 실행 → **프론트엔드 큐 위임** (poll → execute → result)
- 무제한 실행 → **Input Gate 검사** (type/key 액션에 가드레일 적용)
- 스텝 간 독립 → **히스토리 누적** (이전 행동 참조하여 반복 방지)

## Sandbox 보안 강화 (자체 개발)

open-computer-use의 Docker 패턴에서 영감을 받되, 보안을 대폭 강화:

| 기능 | open-computer-use | BoanClaw Sandbox |
|------|-------------------|-----------------|
| 환경변수 | 전체 상속 | 위험 변수 삭제 (SSLKEYLOGFILE, NODE_OPTIONS 등 12종) |
| .env 파일 | 그대로 노출 | /dev/null 마운트로 차단 |
| 실행 권한 | root | 비root (boan:2000) + gosu |
| 네트워크 | 무제한 | MITM 프록시 경유 (허용목록만) |
| 자격증명 | 평문 환경변수 | AES 암호화 + 실행시점 주입 |
| Git | 무제한 | Guard 래퍼 (위험 명령 차단) |

## BoanClaw 고유 혁신

### 1. S4 영역 분리 모델
기존 claw 프로젝트에는 없는 보안 영역 개념. 데이터와 인프라를 같은 체계로 분류하고, 영역 간 정보 이동을 게이트로 제어.

### 2. 3-Tier 자기진화 가드레일
단순 규칙 기반이 아닌 LLM 기반 가드레일. wiki가 인간 결정을 학습하고, 헌법 개정까지 자동 제안.

### 3. 사용자 신뢰 모델 (Deny/Ask/Allow)
같은 가드레일 판정에 대해 사용자별로 다른 처리. 보안과 편의성의 균형을 사용자 단위로 조절.

### 4. Credential 플레이스홀더 체계
`{{CREDENTIAL:name}}` 시스템으로 실제 키가 절대 UI/로그/LLM에 노출되지 않음. 실행 시점에만 주입.

### 5. 파일 전송 가드레일
S2→S1 파일 전송 시 파일 내용을 가드레일로 검사. 폴더 전송 차단. S1→S2는 무조건 통과 (높→낮 원칙).

### 6. OpenClaw Supply-Chain 검증
타 Claw 는 외부 npm 패키지를 그대로 끌어다 씀. BoanClaw 는 OpenClaw 자체를:
1. **빌드 시점**에 명시 버전 핀 + `package.json` 검사 + `openclaw.mjs` sha256 기록
2. **컨테이너 시작 시**에 두 값 재계산해서 변조 여부 검사
3. **선택적 allowlist** (`BOAN_OPENCLAW_ALLOWED_VERSIONS`) 로 운영 중에도 좁히기 가능

mismatch 면 sandbox 가 fail-closed 종료. supply-chain 공격(악성 publish, registry 변조, 컨테이너 침투 후 바이너리 교체) 을 모두 막음.
