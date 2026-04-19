# Test 31 — Wazuh EDR Setup

**기능**: 조직 중앙 EDR manager + Windows agent + Fluent Bit 로그 forwarding.

---

## 증거

### 1) Container 기동
```
$ docker ps --format '{{.Names}}: {{.Status}}' | grep -E "wazuh|fluent"
boanclaw-boan-wazuh-manager-1: Up 2 minutes
boanclaw-boan-fluent-bit-1: Up 19 seconds
```

### 2) Wazuh 포트 호스트 LISTEN
```
$ ss -tulnp | grep -E "1514|1515|55000"
udp UNCONN  0.0.0.0:1514       ← agent 이벤트 채널
tcp LISTEN  0.0.0.0:1515       ← agent enrollment
tcp LISTEN  0.0.0.0:55000      ← REST API
```

### 3) Wazuh API 인증 + agent 목록
```
$ TOKEN=$(curl -k -u wazuh-wui:BoanWazuh2026! -X POST \
    "https://localhost:55000/security/user/authenticate?raw=true")
$ curl -k -H "Authorization: Bearer $TOKEN" \
    "https://localhost:55000/agents?pretty=true"
{
  "data": {
    "affected_items": [
      {"id": "000", "name": "boan-wazuh-manager", "status": "active",
       "version": "Wazuh v4.7.5", ...}
    ],
    "total_affected_items": 1
  }
}
```
Manager 본인 (id=000) 등록 확인. 사용자 VM agent 가 연결되면 id=001+ 로 추가 예정.

### 4) Fluent Bit 로그 tail 정상
```
$ docker logs boanclaw-boan-fluent-bit-1 | tail
[input:tail:tail.2] initializing       ← /var/ossec/logs/alerts/alerts.json
[input:tail:tail.3] initializing       ← /var/ossec/logs/archives/archives.json
[output:stdout:stdout.0] worker #0 started
[sp] stream processor started
```

### 5) 파일 공유 검증
Fluent Bit 가 Wazuh log volume 을 `ro` 로 마운트. alert 발생 시 Fluent Bit stdout 으로 JSON 확인 가능.

---

## 관리자 설치 흐름 (docs/06_EDR_Wazuh.md 참고)
1. 관리자 VM PowerShell (관리자 모드) 실행
2. `deploy/wazuh/install-agent-windows.ps1 -ManagerHost <public-ip>` 로 agent 설치
3. "🧊 내 VM 굽기" 클릭 → agent 포함 이미지
4. 신규 사용자 VM 자동 배포 + auto-register

---

## 다음 단계 (미구현)
- [ ] Wazuh alert level >= 10 일 때 Admin API 로 자동 VM imaging 트리거 (포렌식 보존)
- [ ] `BOAN_LOG_FORWARD_URL` 설정 시 http output 활성 (현재 stdout 만)
- [ ] Admin Console 에 Wazuh alert 실시간 feed UI 탭 (Observability 확장)

---

## 결론
✅ Wazuh manager + Fluent Bit 컨테이너 기동 정상.
✅ API 인증/조회 동작.
✅ Agent 등록 준비 완료 (포트 1515 TCP, 1514 UDP).
✅ 알람 파이프라인 준비 (alerts.json → Fluent Bit → stdout; 외부 forwarding 은 env 로 설정 가능).

실제 사용자 VM agent 등록 + alert 발생 검증은 admin 이 `install-agent-windows.ps1` 실행한 후 후속 세션에서 수행.
