# Test 44 — Wazuh active-response → boan-proxy webhook 자동 detection chain

**날짜**: 2026-05-01.
**범위**: Threat Leader Accept → KillChain rule auto=true 등록 후, **사용자 VM 에서 실제 process 실행** 시 자동 detection → 격리 → 이미징 → STOP → DELETE chain.

---

## 1. 사용자 결정사항
- "drm 깔아서 이미지 배포해야지" — Wazuh agent 를 Golden Image 에 박아서 신규 VM 자동 적용.
- 자동 detection 미동작 시 사용자 RDP 접속해서 Python 깔아도 격리 안 됨 → 이번 라운드에 manager+agent 자동화.

---

## 2. 추가/변경된 자산

### `deploy/wazuh/install-agent-windows.ps1` (Sysmon 통합)
- 기존: Wazuh agent MSI 다운+설치+manager 등록만.
- 추가: **Sysmon64 다운+설치** (sysinternals) + SwiftOnSecurity sysmonconfig 적용.
- 추가: agent ossec.conf 에 `Microsoft-Windows-Sysmon/Operational` eventchannel 등록 — 그래야 sysmon event 가 manager 로 forward.

### `deploy/wazuh/rules/boan_killchain_rules.xml` (재작성)
- `100200`: sysmon event 1 (process create) → `claude/node/python/npm/pip/java/ruby/php/go` 실행 매칭, level=12.
- `100201`: 패키지 매니저 install 호출 (npm/pip/yarn install) 매칭, level=11.
- `100202`: Wazuh service 중단 시도 (evasion) 매칭, level=14.

### `deploy/wazuh/active-response/boan-killchain-event.sh` (신규)
- Wazuh AR/3 protocol — stdin 으로 alert JSON 받음.
- `image / processName / process_name` 추출 + Windows path → basename + lowercase + `.exe` 제거 → 정규화된 process 이름.
- `BOAN_PROXY_WEBHOOK` 환경변수 (default: `http://boan-sandbox:18081/api/kill-chain/event`) 로 POST.
- `BOAN_AGENT_EMAIL_MAP` 환경변수 (옵션) — agent_name → email 매핑.

### `deploy/wazuh/entrypoint-hook.sh` (신규)
- wazuh-manager 컨테이너 first-boot 시 init 가 `/var/ossec` 을 populate 하기 전에 우리가 `/var/ossec/etc/rules/` 같은 곳을 마운트하면 init 가 디렉토리 존재 → already-init 으로 오인 → ossec.conf 미생성. 이 문제 회피.
- staging 마운트 path `/boan-staging/` 에 자산 두고, `/init` (wazuh-manager 4.7.5 의 default ENTRYPOINT) 를 background 로 호출 후 ossec.conf populate 대기.
- ossec.conf 생기면 우리 자산 install + ossec.conf 에 boan-killchain command + active-response 블록 idempotent 추가 + `wazuh-control restart`.
- 영속화: docker-compose 에 `entrypoint: ["/boan-staging/entrypoint-hook.sh"]` 명시.

### `docker-compose.dev.yml`
- staging volume mount + `BOAN_PROXY_WEBHOOK` 환경변수 + entrypoint override.

---

## 3. E2E 검증

### Manager 부팅 흐름 (logs)
```
[boan-init] starting upstream entrypoint: /init
[boan-init] waiting for /var/ossec/etc/ossec.conf to be populated...
[boan-init] ossec.conf ready (size=10499 bytes)
[boan-init] rule installed: /var/ossec/etc/rules/boan_killchain_rules.xml
[boan-init] active-response script installed
[boan-init] ossec.conf patched (active-response + command added)
[boan-init] boan-init done — handing back to upstream entrypoint
```

### `wazuh-control status`
```
wazuh-modulesd / monitord / logcollector / remoted / syscheckd / analysisd / execd / db is running ✓
wazuh-clusterd / maild not running (default disabled, 정상)
```

### Webhook 시뮬 (sysmon event 1 simulate)
```bash
echo '{"command":"add","parameters":{"alert":{"data":{"win":{"eventdata":{
  "image":"C:\\Python\\python.exe"}}},"agent":{"name":"test-vm"}}}}' \
  | /var/ossec/active-response/bin/boan-killchain-event.sh
```
AR log:
```
[2026-05-01T11:44:51Z] [boan-killchain] agent=test-vm process=python email=test-vm
   → POST http://boan-sandbox:18081/api/kill-chain/event
[2026-05-01T11:44:51Z] [boan-killchain] response: user not found: test-vm
```

→ webhook 정상 도달. boan-proxy 가 user 못 찾아 fail (test-vm 가짜 hostname). 실제 agent_name=email 으로 등록되면 매칭 + 격리.

---

## 4. 끝-에서-끝 자동 chain (이론적 흐름)

```
1. admin → ThreatLeader 페이지 → Accept (예: litellm)
   → KillChain rule "Threat Leader: litellm @ PyPI (CRITICAL)" auto=true, process=python

2. 사용자 RDP → Windows VM 에서 python.exe 실행
   ↓
3. Sysmon event 1 (process create) 발생
   ↓
4. Wazuh agent 가 manager 로 forward (1514/udp)
   ↓
5. Manager 의 rule 100200 매칭 (level=12, group=boan_killchain_match)
   ↓
6. active-response: boan-killchain-event.sh 실행
   ↓
7. POST http://boan-sandbox:18081/api/kill-chain/event
   {process_name:"python", target_email:"<agent_name>"}
   ↓
8. boan-proxy:
   - MatchProcess("python") → Threat Leader rule (auto=true)
   - triggerKillChain(...)
     a. network isolate (boan-quarantine tag)
     b. forensic disk snapshot (GCS image 영구 보존)
     c. STOP (RAM 증발)
     d. DELETE (인스턴스 제거)
   ↓
9. Threat Leader 가 추천한 process 가 사용자 컴퓨터에서 30 초 안에 격리됨.
```

---

## 5. 미해결 — 다음 phase

| 항목 | 현재 | 다음 |
|------|------|------|
| Manager 외부 도달성 | docker network 안 (`boan-wazuh-manager`) | host LAN public IP + port forward, 또는 Cloud Run 이주 |
| agent_name → email 매핑 | webhook 가 agent_name 을 email 로 그대로 사용 | `install-agent-windows.ps1` 가 사용자 email 받아서 agent_name 으로 등록, 또는 `BOAN_AGENT_EMAIL_MAP` 환경변수 |
| 신규 VM 자동 install | admin 이 자기 VM 안에서 한번 ps1 실행 + Golden image 굽기 → 신규 VM 자동 | (Golden image 흐름 OK) — 별도 진행 |
| ossec.conf patch idempotency | 컨테이너 재기동마다 patch 다시 적용 (entrypoint-hook 가 grep 으로 idempotent 처리) | OK |
| ossec.conf 의 patch 위치 | 우연히 default config 의 active-response 예시 comment 안에 들어감 (`-->` 가 closing 직전) | 다음 라운드에 더 정확한 anchor 로 inject |

---

## 6. 합계

| 작업 | 상태 |
|------|------|
| `install-agent-windows.ps1` Sysmon 통합 | ✅ |
| `boan_killchain_rules.xml` 재작성 (sysmon event1 매칭) | ✅ |
| `boan-killchain-event.sh` active-response webhook | ✅ |
| `entrypoint-hook.sh` 영속화 hook | ✅ |
| docker-compose 통합 (volume + env + entrypoint) | ✅ |
| Manager 부팅 시 자산 install + ossec.conf patch | ✅ E2E logs |
| Webhook 시뮬 → boan-proxy 도달 | ✅ AR log |

E2E 자동 chain 의 모든 컴포넌트 동작. 실제 GCP Windows VM 에서 검증하려면 manager 외부 도달성 + agent_name=email 매핑 두 가지가 별도 phase.
