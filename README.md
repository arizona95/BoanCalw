# BoanClaw

> 보안 격리 + 정보 흐름 통제 + 가드레일이 내장된 OpenClaw 래퍼.
> 사용자가 코딩 에이전트를 굴리는 동안 자격증명/코드/데이터가 외부로 새지 않도록 구조적으로 막는다.

---

## ⚡ 한 줄 설치 (Linux / WSL)

```bash
git clone https://github.com/arizona95/BoanCalw.git ~/boanclaw && cd ~/boanclaw && bash install.sh
```

설치 완료 후 브라우저에서 **http://localhost:19080** 접속.

### 업데이트

```bash
cd ~/boanclaw && git pull && bash install.sh
```

### Windows 사용자

Windows 에서는 WSL2 안에서 설치합니다.

```powershell
# PowerShell (관리자) — WSL 설치 (최초 1회, 재부팅 필요)
wsl --install
```

재부팅 후 WSL Ubuntu 터미널에서:

```bash
# Docker 설치 (최초 1회)
sudo apt update && sudo apt install -y docker.io docker-compose-plugin git curl
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
# 여기서 로그아웃 후 재로그인 (또는 newgrp docker)

# BoanClaw 설치
git clone https://github.com/arizona95/BoanCalw.git ~/boanclaw && cd ~/boanclaw && bash install.sh
```

Windows 브라우저에서 **http://localhost:19080** 으로 접속 (WSL2 localhost 포워딩 자동).

### git 이 없다면

<details>
<summary>Ubuntu / Debian</summary>

```bash
sudo apt update && sudo apt install -y git docker.io docker-compose-plugin curl
sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker
```
</details>

<details>
<summary>CentOS / RHEL / Fedora</summary>

```bash
sudo dnf install -y git docker docker-compose-plugin curl
sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker
```
</details>

<details>
<summary>macOS</summary>

```bash
brew install git
# Docker Desktop: https://docs.docker.com/desktop/install/mac-install/
```
</details>

### Docker Credential 오류 시

Docker Desktop 을 설치했다가 제거한 환경에서 `docker-credential-desktop.exe: not found` 오류가 나면:

```bash
# ~/.docker/config.json 에서 credsStore 제거
python3 -c "
import json
with open('$HOME/.docker/config.json') as f: c = json.load(f)
c.pop('credsStore', None)
with open('$HOME/.docker/config.json', 'w') as f: json.dump(c, f, indent=2)
"
```

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
