# Credential Vault 설계 — S3 → S4 분리 (Phase 1 ✅) + GCP KMS (Phase 2 진행 중)

## 0. 현재 상태 한눈에

| Phase | 항목 | 상태 |
|---|---|---|
| Phase 1 | credential-filter 를 sandbox 밖 독립 컨테이너로 분리 | ✅ 완료 |
| Phase 1 | sandbox 의 `boan-cred-*` volume mount 제거 | ✅ 완료 |
| Phase 1 | sandbox → credential-filter HTTP API 일원화 | ✅ 완료 |
| Phase 2 | GCP Cloud KMS envelope encryption | 🟡 설계 완료, 구현 대기 |
| Phase 2 | KMS 자동 키 로테이션 | ⏳ |

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

### Phase 2: GCP Cloud KMS 연동 (진행 중)

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
