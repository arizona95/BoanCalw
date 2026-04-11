# BoanClaw

> 보안 격리 + 정보 흐름 통제 + 가드레일이 내장된 OpenClaw 래퍼.
> 사용자가 코딩 에이전트를 굴리는 동안 자격증명/코드/데이터가 외부로 새지 않도록 구조적으로 막는다.

---

## ⚡ 한 줄 설치 (Linux)

### Prerequisites (fresh Ubuntu/Debian 박스 기준)

```bash
sudo apt update
sudo apt install -y curl tar coreutils docker.io docker-compose-plugin
sudo usermod -aG docker $USER && newgrp docker     # 로그아웃 후 재로그인 권장
sudo systemctl enable --now docker
```

CentOS/RHEL/Fedora:
```bash
sudo dnf install -y curl tar coreutils docker docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker
```

### 설치 한 줄

```bash
curl -fsSL https://<your-host>/install.sh | bash
```

설치 스크립트가 자동으로:

1. `curl`, `tar`, `sha256sum`, `docker`, `docker compose` 설치 여부 + 데몬 동작 확인
2. **소스 tarball** (`boanclaw-<version>.tar.gz`, ~370 KB) 을 같은 호스트에서 다운로드
3. **sha256 무결성 검증** — 빌드 시점에 박힌 해시와 일치 확인 (mismatch → 즉시 종료)
4. `$HOME/boanclaw/` 에 소스 추출
5. `~/Desktop/boanclaw/` 마운트 폴더 생성 (S3↔S2 공유 디렉토리)
6. 호스트 UID/GID 자동 감지 → sandbox 빌드 args 로 전달 (호스트에서 본인 소유 파일로 보임)
7. Docker 이미지 빌드 + 컨테이너 시작 (`scripts/rebuild.sh` — proxy/sandbox/console 동시 빌드)
8. **OpenClaw supply-chain 검증** — 빌드 시점 핀 + sha256 을 sandbox entrypoint 가 매 시작마다 재검사 (fail-closed)
9. `http://localhost:19080` 헬스체크 후 안내 출력

업데이트는 같은 명령을 다시 실행하면 됨 — 기존 `$HOME/boanclaw` 을 재추출 + rebuild.

> **`<your-host>` 가 무엇인가**: BoanClaw 는 npm/apt/brew 같은 공식 패키지 채널에 올려져 있지 않습니다. 누구든지 이 한 줄 인스톨러를 운영하려면 본인이 호스팅 해야 합니다. 두 단계:

### 인스톨러 빌드 + 호스팅 (운영자 절차)

`scripts/build-installer.sh` 가 두 파일을 만들어줍니다:
- `dist/install.sh` — 작은 shim (~3.7 KB), 위에서 사용자가 curl 로 받는 그 파일
- `dist/boanclaw-<version>.tar.gz` — 실제 소스 (~370 KB)

```bash
# 1. 두 파일 빌드 (BASE_URL 은 이 두 파일이 올라갈 prefix)
./scripts/build-installer.sh https://github.com/your-org/boanclaw/releases/download/v2026.4.10

# 2. dist/ 안의 두 파일을 같은 prefix 에 호스팅
#    옵션 A — GitHub release:
gh release create v2026.4.10 dist/install.sh dist/boanclaw-2026.4.9.tar.gz

#    옵션 B — 사내 정적 호스팅 (예: nginx /var/www/boanclaw/):
sudo cp dist/* /var/www/boanclaw/

#    옵션 C — 로컬 테스트 (한 박스 안에서 검증):
./scripts/build-installer.sh http://localhost:18765
(cd dist && python3 -m http.server 18765) &
curl -fsSL http://localhost:18765/install.sh | bash
```

shim 안에는 빌드 시점에 박힌 `BOANCLAW_TARBALL_URL` + `BOANCLAW_TARBALL_SHA256` 가 있어서, 사용자가 받은 shim 이 변조됐거나 tarball 이 중간자 공격으로 바뀌면 즉시 sha256 mismatch 로 fail-closed 종료.

### 이미 소스가 있는 경우 (개발 환경)

```bash
cd /path/to/BoanClaw
./install.sh
```

스크립트 옆에 `docker-compose.dev.yml` 이 있으면 자동 감지 → clone/download 없이 그 디렉토리에서 바로 빌드.

---

## 🧱 BoanClaw 가 뭘 하는가

OpenClaw 같은 코딩 에이전트는 강력하지만 그대로 쓰면 **자격증명·소스코드·고객 데이터**가 외부 LLM / 임의 외부 서버로 새기 쉽다. BoanClaw 는 OpenClaw 를 그대로 둔 채 그 주위에 다음 4개 구조를 두른다:

1. **S1–S4 영역 분리** — 데이터·실행·정책·외부 4 단계 신뢰 영역. 영역 간 이동에는 항상 게이트 통과.
2. **G1/G2/G3 가드레일** — 정규식 → 헌법 LLM → 자기진화 Wiki LLM 의 3 단 검사.
3. **Credential / Network Gateway** — 자격증명은 S4 vault 에 격리, 외부 통신은 fail-closed 화이트리스트.
4. **OpenClaw 무결성 검증** — supply-chain 공격 차단. 핀된 버전 + 바이너리 sha256 을 매 컨테이너 시작 시 검증.

자세한 아키텍처는 [`docs/03_구성도.md`](docs/03_구성도.md) 참고.

---

## 🗺️ 신뢰 영역 (S1–S4)

| 영역 | 정의 | 대표 컴포넌트 | 호스트 경로 |
|---|---|---|---|
| **S4** | Credential 격리 — AES 키, 암호화된 vault, 정책 서명 키 | `boan-credential-filter`, `boan-policy-server`, `boan-audit-agent` | named volumes (`/etc/boan-cred`, `/data/credentials`) — sandbox 마운트 금지 |
| **S3** | Control plane — 호스트 PC, 관리 콘솔, 프록시 | `boan-admin-console`, `boan-proxy`, `boan-llm-registry`, `boan-whitelist-proxy`, `boan-guacamole` | `~/Desktop/boanclaw` ↔ S2 bind mount |
| **S2** | Sandbox 실행 영역 — OpenClaw, 에이전트, 코드 실행 | `boan-sandbox` (내장: openclaw, boan-agent, 내장 proxy, onecli) | `/home/boan/Desktop/boanclaw` (= S3 bind mount) |
| **S1** | 외부 — GCP Windows workstation, 외부 LLM API, 인터넷 | GCP RDP (Guacamole 경유), Anthropic/OpenAI API, `boan-computer-use` | `/data/rdp-transfer/<email>` (RDP 가상 드라이브 staging) |

기본 mount 구조:

```
호스트(S3)                              sandbox(S2)                          GCP Win(S1)
~/Desktop/boanclaw/      ←bind mount→  /home/boan/Desktop/boanclaw/         <BoanClaw 가상 드라이브>
                                       /data/rdp-transfer/<email>/   ←RDP virtual drive→
```

---

## 🛡️ 게이트 (G1 / G2 / G3)

| Gate | 적용 | 평가자 | 실패 시 |
|---|---|---|---|
| **G1** | 모든 사용자 (allow 포함) | 정규식 (private key, API token, JWT, password=, export SECRET=) | `credential_required` — 즉시 차단 |
| **G2** | `ask` / `deny` 사용자 | 헌법 + 보안 LLM | `block` 또는 `ask` (→ G3) — LLM 미응답 시 fail-closed |
| **G3** | G2 가 `ask` 일 때만 | Wiki LLM (HITL training log few-shot 학습) | `block` 또는 `ask` (→ HITL 승인 큐) — fail-closed |

G3 는 인간 결정 누적 → G1 정규식 / G2 헌법 자동 개정 제안 (Approvals > Constitution Diff 에서 소유자 검토).

게이트 적용 범위 (모두 S1 방향 — 높→낮):

- 키보드 / 클립보드 / 채팅 입력
- Computer-Use type/key 액션
- 파일 S2→S1 전송 (S1→S2 는 면제)

---

## 🔐 OpenClaw 무결성 검증 (Supply-Chain)

`npm install -g openclaw@latest` 처럼 unpinned 설치는 supply-chain 공격에 무방비입니다. BoanClaw 는 두 단계로 막습니다:

1. **빌드 시점** (`Dockerfile`):
   - `ARG OPENCLAW_VERSION=2026.4.9` 로 명시 핀
   - 설치 직후 `package.json` 의 version 을 검사 — 빌드 mismatch 시 image build 실패
   - `openclaw.mjs` 의 sha256 을 `/opt/boanclaw-meta/openclaw.mjs.sha256` 에 기록

2. **런타임** (`entrypoint.sh`):
   - `package.json` version 재검사 → expected 와 mismatch 면 컨테이너 즉시 종료
   - `openclaw.mjs` sha256 재계산 → 저장된 값과 mismatch 면 컨테이너 즉시 종료
   - 옵션: `BOAN_OPENCLAW_ALLOWED_VERSIONS` 환경변수가 있으면 그 콤마구분 allowlist 에도 포함되어야 통과 — 정책 서버나 운영자가 동적으로 좁힐 수 있는 두 번째 레이어

새 OpenClaw 버전을 허용하려면 `Dockerfile` 의 `OPENCLAW_VERSION` 을 올리고 `scripts/rebuild.sh` — 새 sha256 이 자동으로 다시 기록됩니다.

---

## 🚀 일상 사용

```bash
# 시작 / 중지
cd ~/boanclaw
docker compose -f docker-compose.dev.yml up -d
docker compose -f docker-compose.dev.yml down

# 코드 변경 후 (proxy/sandbox/console 동시 빌드 보장)
./scripts/rebuild.sh

# 관리 콘솔
open http://localhost:19080
```

| 포트 | 서비스 |
|---|---|
| `19080` | 관리 콘솔 (admin-console) |
| `18080` | boan-proxy MITM (HTTP_PROXY 용) |
| `18081` | boan-proxy admin API |
| `8081` | policy-server |
| `8082` | credential-filter (S4) |
| `8084` | audit-agent |
| `8086` | llm-registry |
| `8090` | computer-use |

---

## 📚 문서 색인

| 파일 | 내용 |
|---|---|
| [`docs/01_보안철학.md`](docs/01_보안철학.md) | S1–S4, 정보 흐름, fail-closed 원칙 |
| [`docs/02_보안요건.md`](docs/02_보안요건.md) | BR-/ZR-/SB-/IF- 요건 매트릭스 |
| [`docs/03_구성도.md`](docs/03_구성도.md) | 전체 아키텍처, 정보 흐름 엣지 그래프, 마운트 경로 |
| [`docs/04_보안게이트웨이.md`](docs/04_보안게이트웨이.md) | Input/Credential/Network Gate 동작 |
| [`docs/05_LLM가드레일.md`](docs/05_LLM가드레일.md) | G1/G2/G3 평가 알고리즘 |
| [`docs/06_타Claw보안비교.md`](docs/06_타Claw보안비교.md) | OpenClaw / open-computer-use 와 비교 |
| [`docs/07_테스트명세서.md`](docs/07_테스트명세서.md) | 기능별 수동/자동 테스트 |
| [`docs/08_에이전트보안고려사항.md`](docs/08_에이전트보안고려사항.md) | Anthropic agent 가이드라인 매핑 |
| [`docs/09_Credential_Vault_설계.md`](docs/09_Credential_Vault_설계.md) | S4 분리 + GCP KMS 로드맵 |

---

## ⚙️ 환경 변수 빠른 참조

| 변수 | 기본값 | 의미 |
|---|---|---|
| `BOAN_HOST_MOUNT_ROOT` | `~/Desktop/boanclaw` | S3↔S2 공유 디렉토리 (호스트 측) |
| `BOAN_UID` / `BOAN_GID` | 호스트 사용자 | sandbox `boan` 사용자 UID/GID |
| `BOAN_OPENCLAW_ALLOWED_VERSIONS` | (없음) | 콤마구분 OpenClaw 버전 allowlist (런타임 추가 검증) |
| `BOAN_GCP_ORG_ID` | (없음) | GCP workstation 사용 시 조직 ID |

---

## 🧪 개발

```bash
# Go 단위 테스트 (proxy)
cd src/packages/boan-proxy && go test ./... -count=1

# TypeScript 단위 테스트 (admin-console)
cd src/packages/boan-admin-console && npm test

# 전체 통합 테스트
./scripts/test.sh
```

코드 변경 시 메모리 규칙: **proxy / sandbox / console 은 항상 함께 rebuild** — `scripts/rebuild.sh` 가 셋을 자동으로 묶어서 빌드합니다 (sandbox 가 빌드 시점에 boan-proxy 바이너리를 임베드하기 때문).
