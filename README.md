# BoanClaw

> 보안 격리 + 정보 흐름 통제 + 가드레일이 내장된 OpenClaw 래퍼.
> 사용자가 코딩 에이전트를 굴리는 동안 자격증명·코드·고객 데이터가 외부로 새지 않도록 **구조적으로** 막습니다.

---

## 1. 한 줄 설치

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/arizona95/BoanCalw/main/install.sh)
```

설치가 끝나면 브라우저에서 **<http://localhost:19080>** 접속.

---

## 2. 조직 가입 요청

브라우저 화면 → **"가입 요청"** 클릭 → 두 가지 입력:

- **조직서버 URL** — 조직 소유자에게서 받은 값 (e.g. `https://boan-policy-server-sds-corp-xxxxx.run.app`)
- **회사 이메일**

제출하면 소유자에게 가입 요청이 전달되고, 승인 후 이메일 SSO 로 로그인 가능합니다. *토큰 / 조직 ID 는 입력할 필요 없습니다 — URL 하나로 끝.*

> **조직 소유자(관리자)** 는 GCP 인프라 배포가 먼저 필요합니다 → [`docs/00_관리자_설치.md`](docs/00_관리자_설치.md) 참고.

---

## 3. 환경별 설치 가이드

### case 1 — Linux / WSL2 (Docker 이미 있음)
위의 한 줄 설치 그대로 실행. 끝.

### case 2 — Windows (WSL 이 없는 경우)
PowerShell (관리자) 에서:
```powershell
wsl --install
```
재부팅 → WSL Ubuntu 터미널 → Docker 설치:
```bash
sudo apt update && sudo apt install -y docker.io docker-compose-plugin curl
sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker
```
그 다음 위의 한 줄 설치. Windows 브라우저에서 `http://localhost:19080` 자동 포워딩.

### case 3 — Linux 인데 Docker 가 없는 경우
**Ubuntu / Debian**
```bash
sudo apt update && sudo apt install -y docker.io docker-compose-plugin curl
sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker
```
**CentOS / RHEL / Fedora**
```bash
sudo dnf install -y docker docker-compose-plugin curl
sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker
```
설치 후 위의 한 줄 설치 실행.

### case 4 — macOS
Docker Desktop 설치 (<https://docs.docker.com/desktop/install/mac-install/>) → 실행 → 위의 한 줄 설치.

### case 5 — `docker-credential-desktop.exe: not found` 에러
Docker Desktop 을 설치했다 제거한 환경에서 발생합니다.
```bash
python3 -c "
import json
with open('$HOME/.docker/config.json') as f: c = json.load(f)
c.pop('credsStore', None)
with open('$HOME/.docker/config.json', 'w') as f: json.dump(c, f, indent=2)
"
```

### 업데이트
```bash
cd ~/boanclaw && bash install.sh
```

---

## 🧱 BoanClaw 가 뭘 하는가

OpenClaw 같은 코딩 에이전트는 강력하지만 그대로 쓰면 **자격증명·소스코드·고객 데이터** 가 외부 LLM 으로 새기 쉽습니다. BoanClaw 는 OpenClaw 를 그대로 둔 채 그 주위에 5 개 구조를 두릅니다:

1. **S1–S5 영역 분리** — 데이터·실행·정책·외부·클라우드 5 단계 신뢰 영역. 영역 간 이동에는 항상 게이트 통과.
2. **G1/G2/G3 가드레일** — 정규식 → **보안 LLM (헌법)** → **보안 LLM (자기진화 wiki)** 의 3 단 검사. *현재 구현은 Ollama (gemma) 이지만, "어떤 보안 모델이든 꽂을 수 있도록" 설계되었음 — Security LLM Registry 가 실제 모델을 결정.*
3. **Cloud Credential Vault** — credential 평문은 GCP Secret Manager (Cloud Run `boan-org-credential-gate`) 에만 존재. 로컬 호스트는 `{{CREDENTIAL:role}}` placeholder 만 소유.
4. **Single Egress (org-llm-proxy)** — 모든 외부 LLM 호출은 Cloud Run `boan-org-llm-proxy` 통과. 로컬은 ollama/anthropic/openai 직접 egress 안 함. LLM 호출 직전 cloud 에서 credential substitute + response credential echo scrub.
5. **OpenClaw 무결성 검증** — supply-chain 공격 차단. 핀된 버전 + 바이너리 sha256 을 매 컨테이너 시작 시 검증.

자세한 아키텍처는 [`docs/02_구성도.md`](docs/02_구성도.md), 보안 LLM 의 역할은 [`docs/04_LLM가드레일.md`](docs/04_LLM가드레일.md) 참고.

---

## 📚 문서 색인

| 파일 | 내용 |
|---|---|
| [`docs/00_관리자_설치.md`](docs/00_관리자_설치.md) | **관리자 (조직 소유자) 용 GCP 배포 가이드** |
| [`docs/01_보안철학.md`](docs/01_보안철학.md) | S1–S5, fail-closed, 정보 흐름 원칙 |
| [`docs/02_구성도.md`](docs/02_구성도.md) | 전체 아키텍처, 컨테이너, 마운트, 정보 흐름 엣지 |
| [`docs/03_보안게이트웨이.md`](docs/03_보안게이트웨이.md) | Input / Credential / Network Gate 동작 |
| [`docs/04_LLM가드레일.md`](docs/04_LLM가드레일.md) | G1/G2/G3 평가 알고리즘 + **보안 LLM 추상화** |
| [`docs/05_Credential_Vault.md`](docs/05_Credential_Vault.md) | S5 vault, Secret Manager, P3 device JWT, P4 revoke/rate-limit |
| [`docs/06_EDR_Wazuh.md`](docs/06_EDR_Wazuh.md) | Wazuh 기반 endpoint detection + Fluent Bit 로그 통합 |
| [`docs/07_타Claw보안비교.md`](docs/07_타Claw보안비교.md) | OpenClaw / open-computer-use 와 비교 |
| [`docs/08_에이전트보안고려사항.md`](docs/08_에이전트보안고려사항.md) | Anthropic agent 가이드라인 매핑 |
| [`docs/09_통합테스트.md`](docs/09_통합테스트.md) | API E2E 테스트 명세 (`/api/test/*`) |
| [`test/Report/`](test/Report/) | 기능 단위 실증 리포트 (실제 cloud/backend 증거 포함) |

---

## 🚀 일상 사용

```bash
# 시작 / 중지
cd ~/boanclaw
docker compose -f docker-compose.dev.yml up -d
docker compose -f docker-compose.dev.yml down

# 코드 변경 후 (proxy / sandbox / console 동시 빌드 보장)
./scripts/rebuild.sh
```

| 포트 | 서비스 |
|---|---|
| `19080` | 관리 콘솔 (admin-console) |
| `18080` | boan-proxy MITM (HTTP_PROXY 용) |
| `18081` | boan-proxy admin API |
| `8082` | credential-filter (S4 thin forwarder, 평문 저장 X) |
| `8084` | audit-agent |
| `8086` | llm-registry |
| `8090` | computer-use |
| `8091` | boan-org-llm-proxy *(로컬 dev. 프로덕션은 Cloud Run)* |
| `8092` | boan-org-credential-gate *(로컬 dev. 프로덕션은 Cloud Run)* |

---

## 🧪 개발 / 기여

```bash
# Go 단위 테스트 (proxy)
cd src/packages/boan-proxy && go test ./... -count=1

# TypeScript 단위 테스트 (admin-console)
cd src/packages/boan-admin-console && npm test

# 전체 통합 테스트
./scripts/test.sh
```

코드 변경 시 메모리 규칙: **proxy / sandbox / console 은 항상 함께 rebuild** — `scripts/rebuild.sh` 가 셋을 자동으로 묶어서 빌드합니다 (sandbox 가 빌드 시점에 boan-proxy 바이너리를 임베드하기 때문).
