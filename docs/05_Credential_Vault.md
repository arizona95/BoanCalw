# Credential Vault 설계

## 0. 현재 상태 한눈에

| Phase | 항목 | 상태 |
|---|---|---|
| Phase 1 | credential-filter 를 sandbox 밖 독립 컨테이너로 분리 | ✅ 완료 |
| Phase 1 | sandbox 의 `boan-cred-*` volume mount 제거 | ✅ 완료 |
| Phase 1 | sandbox → credential-filter HTTP API 일원화 | ✅ 완료 |
| **Phase 2** | **`boan-org-llm-proxy` (Cloud Run) 단일 egress** | ✅ 완료 (org-per-Cloud-Run, bearer 인증) |
| **Phase 2** | **`boan-org-credential-gate` (Cloud Run + Secret Manager) 로 credential 이관** | ✅ 완료 (로컬 평문/AES 키 제거) |
| **Phase 2** | **로컬 `credential-filter` → thin forwarder 모드** | ✅ 완료 (`BOAN_ORG_CREDENTIAL_GATE_URL` 설정 시) |
| **Phase 3** | **device-signed Ed25519 JWT (디바이스 attestation)** | ✅ 완료 |
| Phase 3 | sandbox egress iptables lockdown (Cloud Run 만 허용) | ⏸ Phase 5+ 연기 (docker 네트워크 재설계 필요) |
| **Phase 4** | **structured audit logging (Cloud Logging 통합)** | ✅ 완료 |
| **Phase 4** | **per-credential revoke + device blocklist** | ✅ 완료 |
| **Phase 4** | **per-device rate limit (sliding window)** | ✅ 완료 |
| Phase 4 | MCP SSE/WebSocket 터널 through credential-gate | ⏸ 사용 사례 없음 (향후 재검토) |
| Phase 5 | TPM sealed device key (host root 탈취에도 키 읽기 불가) | ⏳ |
| Phase 5 | Cloud Load Balancer mTLS (native client cert 검증) | ⏳ |

Phase 2 로 원래 계획하던 "GCP Cloud KMS envelope encryption (DEK+KEK)" 는 **폐기**. 대신 credential 평문을 아예 로컬 호스트에 두지 않는 "cloud-native 스토어 (Secret Manager) 로의 이관" 방식을 선택함. Managed Agent (Anthropic) 가 제시한 credential vault + proxy pattern 과 동일 방향.

## 1. 이전 (deprecated) 구조

```
deprecated:
  boan-sandbox (S2)
    ├─ boan-credential-filter (:8082)  ← sandbox 내부에서 실행 — 위험
    ├─ /etc/boan-cred/aes.key          ← AES 키가 sandbox 에 마운트
    └─ /data/credentials/              ← 암호화된 키가 sandbox 에 마운트

위험:
  1. sandbox 침투 → aes.key 읽기 → 모든 credential 복호화 가능
  2. Anthropic 원칙 위반: "토큰이 sandbox에서 접근 불가능하게 만들어라"
  3. Cloud KMS 미사용 → 키 관리가 파일 시스템 의존
```

## 2. 현재 (Phase 1 완료) 구조

```
구현 완료:
  boan-credential-filter  (S4, 독립 컨테이너)
    ├─ /etc/boan-cred/aes.key       ← 이 컨테이너만 마운트
    ├─ /data/credentials/           ← 이 컨테이너만 마운트
    └─ HTTP :8082                   ← 외부에서 접근 가능한 API

  boan-sandbox  (S2)
    ├─ /etc/boan-cred/   ❌ 없음 (compose 에서 마운트 안 함)
    ├─ /data/credentials ❌ 없음
    └─ credential 필요 시:
         HTTP GET http://boan-credential-filter:8082/credential/{org}/{name}
         → S4 가 복호화한 평문 반환 (메모리만)

  Anthropic 원칙 충족: sandbox 침투해도 AES key 파일이 존재 안 함.
```

## 3. 목표 (Phase 2) 구조 — GCP KMS

## 변경 사항

### Phase 1: credential-filter를 sandbox에서 분리 ✅ 완료

**완료**: boan-sandbox 의 entrypoint.sh 에서 credential-filter 내부 프로세스 실행 로직 제거.
독립 컨테이너로 분리. sandbox volume 공유 제거.

**docker-compose.dev.yml 변경:**
```yaml
# 현재: boan-sandbox volumes에서 cred 관련 제거
boan-sandbox:
  volumes:
    - ${BOAN_HOST_MOUNT_ROOT}:/workspace/boanclaw
    - boan-user-data:/data/users
    - boan-registry-data:/data/registry
    # boan-cred-data, boan-cred-keys 제거

# credential-filter는 이미 독립 컨테이너로 존재 (docker-compose에 있음)
# sandbox 내부의 credential-filter 프로세스만 제거
```

**entrypoint.sh 변경:**
```bash
# 제거: boan-credential-filter 내부 실행
# 변경: BOAN_CREDENTIAL_FILTER_URL을 외부 컨테이너로 지정
export BOAN_ONECLI_CRED_FILTER_URL=http://boan-credential-filter:8082
```

**영향:**
- sandbox에서 /etc/boan-cred/aes.key 접근 불가
- sandbox에서 /data/credentials/ 접근 불가
- credential 조회/등록은 HTTP API(http://boan-credential-filter:8082)로만 가능
- boan-proxy의 credential 주입 경로 변경 없음 (이미 HTTP API 사용)

### Phase 2 (실제 구현) — Secret Manager 기반 cloud-native credential gate ✅

로컬 호스트가 credential 평문을 **한 순간도 보유하지 않는** 구조. Anthropic Managed Agent 의
"credential vault + proxy" 패턴과 동일 아키텍처.

```
┌─ LOCAL (untrusted) ──────────┐     ┌─ GCP Cloud Run ──────────────────┐
│                              │     │                                   │
│  boan-proxy (sandbox 내)    │────▶│  boan-org-llm-proxy-{org}        │
│    {{CREDENTIAL:role}} 만     │     │   /v1/forward                     │
│    envelope 에 담아 전송      │     │   1. host allowlist check         │
│                              │     │   2. credresolver → gate 호출     │
│  boan-credential-filter      │     │   3. placeholder → 평문 substitute │
│    (thin forwarder mode)     │     │   4. upstream POST                │
│    register/get/list 전부     │     │   5. response ScrubEchoes         │
│    cloud 로 proxy            │     │                                   │
│    ❌ 로컬 평문 저장 없음     │     │  boan-org-credential-gate-{org}  │
│                              │◀────│   /v1/resolve (proxy 만 호출)    │
│                              │     │   /v1/credentials/{org} CRUD     │
└──────────────────────────────┘     │       │                           │
                                     │       ▼                           │
                                     │  GCP Secret Manager               │
                                     │   secrets: boan-cred-{org}-{role}│
                                     │   labels: managed-by, org, role   │
                                     └───────────┬───────────────────────┘
                                                 ▼
                                     [ ollama.com / api.anthropic.com ]
```

**핵심 컴포넌트:**

- `boan-org-llm-proxy` (Cloud Run, org 별 1개):
  - 모든 외부 LLM upstream 호출의 유일한 egress.
  - `/v1/forward` 는 bearer 토큰 인증 + host allowlist 검증 + `{{CREDENTIAL:*}}` placeholder 를
    credential-gate 로부터 실제 평문으로 치환한 뒤 upstream 전송.
  - 응답 수신 후 `credresolver.ScrubEchoes` 가 credential 문자열 echo 를 `[REDACTED]` 로 마스킹.
  - 로컬 `boan-proxy` 는 placeholder 만 envelope 에 넣어 전송 → 로컬은 평문 credential 본 적 없음.

- `boan-org-credential-gate` (Cloud Run, org 별 1개):
  - GCP Secret Manager 백엔드.
  - secret 이름: `boan-cred-{sanitized-org}-{sanitized-role}`.
  - secret 라벨: `managed-by=boan-org-credential-gate`, `boan-org={org}`, `boan-role={role}`.
  - `POST /v1/credentials/{org}` : 쓰기 only (응답에 평문 없음)
  - `GET /v1/credentials/{org}` : 메타데이터 목록 (role, 생성/업데이트 시각)
  - `POST /v1/resolve` : org-llm-proxy 만 호출. 평문 반환. 메모리에서 밀리초 단위로만 존재.
  - `DELETE /v1/credentials/{org}/{role}` : 삭제.
  - IAM `allUsers` invoker + bearer 토큰 게이트 (P3 에서 mTLS + device JWT 로 교체 예정).

- 로컬 `boan-credential-filter` (thin forwarder 모드):
  - `BOAN_ORG_CREDENTIAL_GATE_URL` + `_AUTH_TOKEN` 설정 시 모든 op 를 cloud gate 로 proxy.
  - Register → gate POST (로컬 디스크 저장 **skip**).
  - Get → gate `/v1/resolve` (로컬 AES 복호화 건너뜀).
  - List → gate list.
  - `credentials.json` + `aes.key` 는 마이그레이션 기간 동안 fallback 으로만 남아있음.

**envelope 프로토콜 (boan-proxy ↔ org-llm-proxy):**

```jsonc
POST https://boan-org-llm-proxy-{org}-xxxx.a.run.app/v1/forward
Authorization: Bearer {static token}   // P3 에서 JWT 로 대체
{
  "org_id": "sds-corp",
  "caller_id": "boan-proxy",
  "target": "https://ollama.com/api/chat",
  "method": "POST",
  "headers": {"Authorization": "Bearer {{CREDENTIAL:ollama-cloud-key}}"},
  "body_b64": "eyJtb2RlbCI6...",
  "timeout_ms": 180000
}
```

응답:
```jsonc
{
  "status": 200,
  "headers": {...},
  "body_b64": "..."
}
```

**Credential 등록 플로우:**

```
사용자 UI (Credentials 페이지)
  │ POST /api/credential/v1/store {role, key, ttl_hours}
  ▼
boan-proxy (admin.go)
  │ POST http://boan-credential-filter:8082/credential/{org}
  ▼
boan-credential-filter (gate mode)
  │ POST {credential-gate}/v1/credentials/{org}
  │ Authorization: Bearer {gate token}
  ▼
boan-org-credential-gate
  │ secretmanager.CreateSecret (idempotent) + AddSecretVersion
  ▼
GCP Secret Manager
```

**LLM 호출 플로우:**

```
boan-proxy openclaw_provider.go
  │ dispatchLLMRequest(endpoint, headers{x-api-key: "{{CREDENTIAL:ollama-cloud-key}}"}, body)
  │  ├─ 로컬 hosts? → direct (boan-grounding:8000 등)
  │  └─ 외부 hosts? → forwardViaOrgProxy
  ▼
org-llm-proxy /v1/forward
  │ credresolver.ResolveAll: {{CRED:x}} 탐지 → gate 호출 → 치환
  │ http.Do(upstream)
  │ credresolver.ScrubEchoes(response.body)
  ▼
upstream LLM
```

**검증된 불변성:**
- 로컬 `credentials.json` 은 P2 전환 후 단 한 번도 업데이트되지 않음 (마지막 mtime: 2026-04-10).
- 신규 등록된 credential 은 Secret Manager 에만 존재, 로컬 디스크 grep 시 0 hit.
- 전체 LLM call 성공 (ollama GLM-5.1 응답) 하면서도 로컬은 placeholder 만 관찰.

**환경변수:**

| 변수 | 설정 대상 | 값 |
|---|---|---|
| `BOAN_ORG_LLM_PROXY_URL` | boan-proxy (sandbox) | `https://boan-org-llm-proxy-{org}-xxxx.a.run.app` |
| `BOAN_ORG_LLM_PROXY_AUTH_TOKEN` | boan-proxy + org-llm-proxy Cloud Run | 32-byte hex (org 공유) |
| `BOAN_ORG_LLM_PROXY_BYPASS_HOSTS` | boan-proxy | `boan-grounding,boan-llm-registry,...` (로컬 서비스) |
| `BOAN_ORG_CREDENTIAL_GATE_URL` | org-llm-proxy + credential-filter | `https://boan-org-credential-gate-{org}-xxxx.a.run.app` |
| `BOAN_ORG_CREDENTIAL_GATE_AUTH_TOKEN` | org-llm-proxy + credential-filter + gate | 32-byte hex (org 공유) |
| `BOAN_GCP_PROJECT_ID` | credential-gate Cloud Run | `ai-security-test-473701` |

**Terraform 모듈:**
- `deploy/terraform/modules/boan-org-llm-proxy/`
- `deploy/terraform/modules/boan-org-credential-gate/`
- 둘 다 `envs/gcp/main.tf` 에서 wire. 이미지: GCR `gcr.io/{project}/boan-org-{...}:latest`.

---

### Phase 2 대안 (폐기됨) — GCP Cloud KMS envelope encryption

**현재**: 로컬 AES-256 키 파일 (`/etc/boan-cred/aes.key`) — 단, sandbox 에서는 접근 불가 (Phase 1 격리 효과)
**변경**: GCP Cloud KMS envelope encryption — KMS 키가 Google Cloud 에 머무름

```
Envelope Encryption:
  1. credential-filter가 credential 등록 시:
     - 로컬 DEK(Data Encryption Key) 생성
     - DEK로 credential 암호화
     - GCP KMS의 KEK(Key Encryption Key)로 DEK 암호화
     - 암호화된 DEK + 암호화된 credential 저장

  2. credential-filter가 credential 조회 시:
     - GCP KMS에 암호화된 DEK 전송 → 복호화된 DEK 수신
     - DEK로 credential 복호화
     - 응답 반환

  장점:
  - 로컬에 평문 키 없음
  - KMS 접근 권한이 없으면 복호화 불가
  - KMS 감사 로그로 키 사용 추적
  - 키 로테이션 자동 지원
```

**kms.go 변경:**
```go
// 현재: 로컬 파일 기반
func NewLocalKMS(keyPath string) *KMS

// 변경: GCP Cloud KMS 또는 로컬 fallback
func NewKMS(config KMSConfig) *KMS

type KMSConfig struct {
    Provider    string // "gcp" or "local"
    // GCP
    ProjectID   string // BOAN_KMS_PROJECT
    LocationID  string // BOAN_KMS_LOCATION (e.g., "asia-northeast3")
    KeyRingID   string // BOAN_KMS_KEYRING
    KeyID       string // BOAN_KMS_KEY
    // Local fallback
    LocalKeyPath string // /etc/boan-cred/aes.key
}
```

**환경변수:**
```
BOAN_KMS_PROVIDER=gcp          # "gcp" or "local"
BOAN_KMS_PROJECT=my-project
BOAN_KMS_LOCATION=asia-northeast3
BOAN_KMS_KEYRING=boanclaw
BOAN_KMS_KEY=credential-key
```

### Phase 3: Credential 주입 경로 정리

```
현재 주입 경로:
  LLM 호출 시:
    boan-proxy → credential-filter API → 복호화된 키 → HTTP 헤더 주입 → LLM
  
  이 경로는 변경 없음. 다만:
  - credential-filter가 sandbox 밖에 있으므로 sandbox 침투로 키 탈취 불가
  - KMS 복호화는 credential-filter 내부에서만 발생
  - 복호화된 키는 메모리에만 존재, 디스크에 쓰지 않음
```

## 보안 효과

| 항목 | 현재 | 변경 후 |
|------|------|--------|
| AES 키 위치 | sandbox volume (S2 접근 가능) | KMS (S4, sandbox 접근 불가) |
| credential-filter 위치 | sandbox 내부 프로세스 | 독립 컨테이너 (S4) |
| sandbox 침투 시 | aes.key 읽기 → 전체 복호화 | API 호출만 가능, 키 접근 불가 |
| 키 로테이션 | 수동 (파일 교체) | KMS 자동 로테이션 |
| 감사 | 없음 | KMS 감사 로그 |

## 구현 순서

1. ✅ **entrypoint.sh에서 credential-filter 내부 실행 제거** — `[boan-sandbox] credential-filter: external container ...` 로그로 확인
2. ✅ **docker-compose에서 volume 공유 제거** — `boan-cred-keys`, `boan-cred-data` 가 `boan-sandbox.volumes` 에 없음
3. ✅ **sandbox의 credential-filter URL을 외부 컨테이너로 변경** — `BOAN_CREDENTIAL_FILTER_URL=http://boan-credential-filter:8082`
4. ⏳ **kms.go에 GCP Cloud KMS provider 추가** — envelope encryption 구현
5. ⏳ **테스트 추가**: KMS provider unit test, 키 로테이션 시나리오
