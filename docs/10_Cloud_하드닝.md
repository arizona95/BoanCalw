# Cloud 최소 권한 + 네트워크 장벽 가이드

운영 모드에서 GCP Cloud Run 위 3 개 서비스 (`boan-policy-server`, `boan-org-llm-proxy`, `boan-org-credential-gate`) 를 "등록된 디바이스만" 호출 가능하게 하는 방법.

기본 dev/POC 배포는 모두 `allUsers` 가 호출 가능 (편의 우선). prod 에서는 아래 단계를 적용하세요.

---

## 1. 위협 모델

| 공격 | 방어 |
|---|---|
| 외부 스캐너가 무한 호출 → request 비용 폭주 | device JWT fail-closed (이번 PR), Cloud Armor rate-limit |
| Bearer 토큰 1 개 탈취 → 모든 디바이스 행세 | Ed25519 device JWT (P3) — 디바이스 키도 같이 있어야 호출 가능 |
| 도난당한 디바이스 키 무한 사용 | `BOAN_REVOKED_DEVICES` env 즉시 차단 (재배포 X) |
| Runaway agent 가 LLM 호출 폭주 | `BOAN_ORG_LLM_PROXY_RPM` per-device rate limit (default 120 rpm) |
| credential-gate 의 `/v1/resolve` 가 외부에서 호출 가능 | (P5 옵션) `ingress = INTERNAL_LOAD_BALANCER_AND_CLOUD_RUN` + LB 만 노출 |

---

## 2. 3 단계 하드닝 옵션

### Tier 1 — 디바이스 JWT (권장 기본값, 추가 비용 없음)

`terraform.tfvars` 에 디바이스 pubkey 추가:
```hcl
device_pubkeys = "BASE64PUBKEY1,BASE64PUBKEY2,..."
revoked_devices = ""  # 폐기 시 ID 추가
```

→ 3 개 서비스 모두 `BOAN_DEVICE_PUBKEYS` 환경변수가 채워지고, 들어오는 모든 요청 (정확히는 `/org/{id}/v1/*`, `/v1/forward`, `/v1/credentials/*`, `/v1/resolve`) 은 `X-Boan-Device-JWT` Ed25519 서명 토큰을 가져야 합니다. **없으면 401 즉시 반환** — container 내부 진입은 하지만 빠르게 거부 (CPU 비용 적음).

디바이스 pubkey 는 사용자 PC 의 `boan-proxy` 가 첫 부팅 시 `/data/boan-device/identity.json` 에 자동 생성합니다. 관리자는 사용자 가입 시 pubkey 를 받아서 `device_pubkeys` 에 콤마로 추가하면 됩니다 (자동화는 향후 할 일).

폐기:
```hcl
revoked_devices = "DEVICE_ID_1,DEVICE_ID_2"
```
`terraform apply` 후 즉시 차단 (디바이스 키는 그대로 두고 ID 만 차단 — recovery 시 ID 만 빼면 다시 활성).

### Tier 2 — Cloud Run IAM (선택, 큰 차이)

현재 모든 서비스 `allUsers` invoker. 이걸 좁히려면:

**옵션 A — 사용자별 GCP IAM 토큰 발급 (복잡)**
- 사용자에게 Google 계정 필요
- 별도 SSO 프로세스로 short-lived ID token 발급
- BoanClaw 가 매 호출마다 ID token 첨부
- 구현 cost 큼

**옵션 B — credential-gate 만 internal (간단, 부분 적용)**
`/v1/resolve` 는 사실상 `org-llm-proxy` 만 호출 (server-to-server, 같은 GCP 프로젝트 내).
1. credential-gate 의 ingress 를 `INTERNAL_ONLY` 로 변경:
   ```hcl
   module "credential_gate" {
     ...
     ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"
   }
   ```
2. `allUsers` invoker 제거하고 org-llm-proxy SA 만 invoker 로 추가 (terraform module 추가 수정 필요).
3. org-llm-proxy 의 credresolver 는 metadata server 에서 ID token 가져와서 `Authorization: Bearer <id_token>` 헤더로 호출 (코드 변경 필요).

**Trade-off**: 로컬 credential-filter (사용자 PC 의 thin forwarder) 가 더 이상 직접 credential-gate 호출 못 함. 등록/list/삭제 흐름은 policy-server 로 가서 internal proxy 하는 식으로 우회 필요. 코드 수정량 큼.

### Tier 3 — Cloud Armor + HTTPS LB (전면 보호)

Cloud Run 자체는 DDoS 방어 X. Cloud Armor 보안 정책 + HTTPS Load Balancer 앞단 추가:

```hcl
# 1. HTTPS LB 가 Cloud Run 으로 forwarding 하는 backend 생성
# 2. Cloud Armor 정책: 
#    - rate limit (분당 60 요청/IP)
#    - geo allowlist (한국, 미국만)
#    - WAF preset (OWASP top 10)
# 3. Cloud Run ingress 를 INTERNAL_LOAD_BALANCER_AND_CLOUD_RUN 으로 좁힘
```

추가 비용: HTTPS LB ~$18/월 + Cloud Armor 정책 ~$5/월 = **약 $23/월** 추가.

이 모드 적용:
```hcl
cloud_run_ingress = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER_AND_CLOUD_RUN"
```
+ 별도 LB / Armor terraform 모듈 작성 (현재 repo 에 없음, 추가 작업 필요).

---

## 3. 현재 적용 상태 (이 PR 기준)

| 컨트롤 | 상태 |
|---|---|
| boan-org-llm-proxy device JWT fail-closed | ✅ (P3) |
| boan-org-credential-gate device JWT fail-closed | ✅ (P3) |
| boan-policy-server device JWT fail-closed | ✅ (이번 PR 추가) |
| Per-device RPM rate limit | ✅ (default 120 rpm) |
| Revoked device blocklist | ✅ (P4, env 변경 즉시 반영) |
| Audit log (Cloud Logging) | ✅ (P4) |
| Cloud Run ingress 변수화 | ✅ (이번 PR 추가, default=ALL) |
| credential-gate internal-only + SA invoker | ⚠️ (terraform 변수만 준비, 코드 변경은 추가 PR 필요) |
| Cloud Armor + HTTPS LB | ⚠️ (문서만, terraform 모듈 추가 필요) |

---

## 4. 운영자 체크리스트

prod 배포 전:
1. `terraform.tfvars` 에 `org_token` (32-byte hex) 설정
2. 모든 사용자 디바이스 pubkey 수집 → `device_pubkeys` csv
3. `terraform apply` → policy-server `BOAN_DEVICE_PUBKEYS` 가 채워짐
4. 사용자가 가입 후 첫 호출 시 device JWT 자동 부여되는지 audit log 확인
5. 잘못된 pubkey 로 호출 시도 → 401 확인
6. RPM 초과 호출 → 429 확인

장기:
- Tier 2 옵션 B (credential-gate internal-only) 검토 — 가장 큰 보안 win
- 필요 시 Tier 3 (Cloud Armor) — 외부 노출 표면이 명확히 정해진 시점
- Secret Manager 의 secret 들에 IAM condition 추가 (특정 SA + 특정 시간대만 접근 등)
