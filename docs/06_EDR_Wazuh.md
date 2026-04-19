# BoanClaw EDR — Wazuh 통합

## 목적
- **악성코드 킬체인 탐지** (MITRE ATT&CK 매핑 alert)
- **사용자 VM 포렌식 스냅샷** (Feature 1 Golden Image 연계)
- **조직 로그서버 중앙 집계** (Fluent Bit → 외부 SIEM/Loki)

## 아키텍처
```
   Windows VM (user workstation)
   ┌─────────────────────────────┐
   │  Wazuh Agent (4.7.5)        │
   │    • Sysmon event forward   │
   │    • Windows Event Log      │
   │    • FIM (File Integrity)   │
   │    • Registry monitoring    │
   └────────────┬────────────────┘
                │ 1514/udp (events)
                │ 1515/tcp (enroll)
                ▼
   ┌─────────────────────────────┐
   │  boan-wazuh-manager (Docker)│
   │    • Rule engine (5000+     │
   │      built-in MITRE rules)  │
   │    • alerts.json 에 append  │
   │    • REST API :55000        │
   └────────────┬────────────────┘
                │ volume shared
                ▼
   ┌─────────────────────────────┐
   │  boan-fluent-bit (Docker)   │
   │    • tail alerts.json       │
   │    • http out → log server  │
   └────────────┬────────────────┘
                │ BOAN_LOG_FORWARD_URL
                ▼
        조직 로그서버 (Loki/ES/Splunk)
```

## 설치 흐름 (관리자)
1. BoanClaw 로컬 Docker 시작 (이미 실행 중이면 rebuild):
   ```
   cd BoanClaw && ./scripts/rebuild.sh
   ```
   `boan-wazuh-manager` + `boan-fluent-bit` 가 함께 기동.

2. Wazuh manager 확인:
   ```
   docker logs boanclaw-boan-wazuh-manager-1 | tail
   # "wazuh-manager started" 문구 확인
   ```

3. 관리자 VM 안에서 agent 설치 (Personal Computer 탭 → PowerShell):
   ```
   # 1) 스크립트 다운로드 (또는 RDP 파일 전송)
   Invoke-WebRequest -Uri http://<host>/deploy/wazuh/install-agent-windows.ps1 \
       -OutFile C:\install-wazuh.ps1

   # 2) 실행
   PowerShell -ExecutionPolicy Bypass -File C:\install-wazuh.ps1 \
       -ManagerHost <manager-public-ip-or-dns>
   ```

4. Manager 에서 등록 확인:
   ```
   docker exec boanclaw-boan-wazuh-manager-1 /var/ossec/bin/agent_control -l
   # Available agents:
   #    ID: 001, Name: DESKTOP-XYZ, IP: any  (Active)
   ```

5. **Admin Console > Authorization > Users 탭 > "🧊 내 VM 굽기"** 클릭.
   → agent 가 설치된 상태로 golden image 가 찍히고, 이후 신규 사용자 VM 은 부팅 시 자동으로 manager 에 재등록된다.

## 킬체인 탐지 예시
Wazuh 기본 룰셋이 다음을 자동 탐지:
- **Initial Access**: 의심스러운 email 첨부 실행 (T1566)
- **Execution**: PowerShell 인코딩 명령 (T1059.001), Office macro (T1204.002)
- **Persistence**: 레지스트리 Run 키 (T1547.001), 서비스 설치 (T1543.003)
- **Privilege Escalation**: UAC bypass (T1548.002)
- **Defense Evasion**: 프로세스 인젝션 (T1055), 이벤트 로그 삭제 (T1070.001)
- **Credential Access**: LSASS 메모리 덤프 (T1003.001), DPAPI 접근 (T1555.004)
- **Discovery**: net/whoami/ipconfig 체이닝 (T1087, T1033, T1082)
- **Lateral Movement**: SMB/WMI/PsExec (T1021.002)
- **Exfiltration**: 대용량 업로드, DNS 터널링

Alert 이 `/var/ossec/logs/alerts/alerts.json` 에 찍히면 Fluent Bit 가 즉시 forwarding.

## 포렌식 VM 이미징 (Feature 1 연계)
Wazuh 가 Critical alert (level >= 10) 발행 시:
1. Admin Console 이 alert 을 받아서 자동 스냅샷 트리거 (TODO)
2. 또는 수동으로 `/api/admin/workstation/image?target_instance=<instance>` 로 특정 VM 이미지 저장
3. 저장된 이미지는 `projects/<project>/global/images/<name>` — 포렌식 분석 가능 (disk attach to investigation VM)

## 조직 로그서버 연동
`.env` 또는 deploy/config/gcp.env 에:
```
BOAN_LOG_FORWARD_URL=https://log.company.internal/ingest
BOAN_LOG_FORWARD_TOKEN=<api-token>
BOAN_LOG_FORWARD_HOST=log.company.internal
BOAN_LOG_FORWARD_PORT=443
BOAN_LOG_FORWARD_PATH=/ingest
```
Fluent Bit 가 재기동 시 자동 연결.

## 검증 체크리스트
- [ ] `docker ps` 에 boan-wazuh-manager + boan-fluent-bit RUNNING
- [ ] `netstat -tulnp | grep 1514` 호스트에서 1514/udp LISTEN
- [ ] agent_control -l 결과에 적어도 1개 agent Active
- [ ] 관리자 VM 에서 `notepad.exe` 실행 후 1-2분 뒤 `docker exec boan-wazuh-manager cat /var/ossec/logs/alerts/alerts.json | tail` 에 해당 이벤트 alert 표시 (만약 Sysmon 설치 돼 있으면)
- [ ] Fluent Bit stdout 에 wazuh.alerts 태그 찍힘
- [ ] `BOAN_LOG_FORWARD_URL` 설정 시 외부 엔드포인트에 POST 요청 도달

## 운영 주의
- Wazuh manager 메모리 ~500MB 기본. agent 수 늘어나면 증가.
- alerts.json 파일 rotate 는 Wazuh 자체 daily logrotate 사용.
- Agent version mismatch 주의 — manager 4.7.x ↔ agent 4.7.x.
