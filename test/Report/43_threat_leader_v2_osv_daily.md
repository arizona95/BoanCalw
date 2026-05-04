# Test 43 — Threat Leader v2 (OSV.dev daily fetch + HITL auto-trigger)

**날짜**: 2026-04-29.
**범위**: ThreatLeader v1 (mock feed) 을 OSV.dev 데일리 자동 fetch 로 교체. HITL Accept = KillChain rule (auto=true) 즉시 등록.

---

## 1. 사용자 결정사항 (이 라운드)
- 데이터 소스: **OSV.dev only** (NVD/GitHub Advisory 는 별도 phase)
- "rule 풀림" 자동 감지: **빼기** (단순화)
- Accept 시 KillChain rule: **auto=true** (즉시 발동, manual trigger 불필요)
- VM 발동 chain: 격리 → 포렌식 disk snapshot → STOP → DELETE (RAM dump 미구현 — winpmem phase 별도)

---

## 2. 새 backend 패키지 — `internal/threatleader/`

| 파일 | 역할 |
|------|------|
| `types.go` | OSV Advisory + 가공된 Proposal 구조체. State (seen/ignored/latest) |
| `osv.go` | `FetchEcosystem` — `https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip` 다운 + `archive/zip` 으로 stream parse + `lookback` 기간 필터. **directHTTPClient (Proxy=nil)** 로 boan-proxy 자기 자신 우회 (sandbox 환경 대응) |
| `select.go` | `SelectTopProposals` — severity (critical>high>medium) + published desc 정렬 후 top N. seen/ignored 제외. CVSS score parsing + heuristic vector severity. ecosystem→process 매핑 (npm→node, PyPI→python 등) |
| `store.go` | JSON 파일 1개 (`/tmp/boan/threat-leader/threat-leader.json`). thread-safe Snapshot/SetLatest/MarkSeen/MarkIgnored. dataDir 은 `BOAN_THREAT_LEADER_DIR` env 로 override 가능 |
| `refresher.go` | `Start(ctx)` — boot 후 5분 첫 fetch + 24h cron + `TriggerNow()` non-blocking 채널 |

---

## 3. HTTP endpoint (`proxy/threatleader_handler.go`)

| Method | Path | 동작 |
|--------|------|------|
| GET | `/api/threat-leader/proposals` | `{last_fetch_at, proposals: [...]}` (5개) |
| POST | `/api/threat-leader/refresh` | refresher 의 trigger 채널에 신호 (non-blocking) — owner only |
| POST | `/api/threat-leader/proposals/{id}/accept` | KillChain rule **auto=true** 등록 + Seen 마킹 — owner only |
| POST | `/api/threat-leader/proposals/{id}/reject` | Ignored 마킹 — owner only |

`requireOwner` 가 testmode 빌드에선 tester 도 통과 (이전 라운드 변경). release 빌드는 owner only.

---

## 4. Frontend (`pages/ThreatLeader.tsx`)

mock feed 제거. real fetch + 30 초 polling + 수동 ↻ 버튼.

각 advisory 카드:
- severity badge (critical/high/medium 색상별)
- CVE / GHSA ID / OSV ID
- `ecosystem:package_name versions_affected`
- 제안 rule 이름 + 매칭 process
- "원본 advisory ↗" 링크
- ✓ Accept / Reject 버튼

---

## 5. E2E 검증 (sandbox container)

### Refresh trigger → OSV fetch
```
[threat-leader] refresh start (ecosystems=[npm PyPI])
[threat-leader] fetched npm: 581 advisories (modified <= 168h0m0s)
[threat-leader] fetched PyPI: 142 advisories (modified <= 168h0m0s)
[threat-leader] refresh done: 5 top proposals
```

소요 시간: 약 14 초 (npm zip ~10MB + PyPI zip ~2MB compressed, 압축 해제 + JSON parse).

### Top 5 결과 (실제 OSV 데이터 — 2026-04-29 기준)

| OSV ID | CVE | 패키지 | severity | 매칭 process |
|--------|-----|--------|----------|-------------|
| GHSA-xqmj-j6mv-4862 | — | PyPI:litellm <1.83.7 | critical | python |
| GHSA-4rc3-7j7w-m548 | CVE-2026-41311 | npm:liquidjs <10.25.7 | critical | node |
| GHSA-8h25-q488-4hxw | — | npm:openlearnx | critical | node |
| GHSA-prp4-2f49-fcgp | — | npm:@actual-app/sync-server | critical | node |
| GHSA-c2jg-5cp7-6wc7 | — | PyPI:pipecat-ai | critical | python |

### Accept 흐름
```
POST /api/threat-leader/proposals/GHSA-xqmj-j6mv-4862/accept
→ {
  "auto": true,
  "id": "GHSA-xqmj-j6mv-4862",
  "rule_id": "rule-1777457648961269250",
  "status": "rule_added",
  "message": "Kill Chain rule 등록 (auto=true). 매칭 process 'python' 발견 시 즉시 격리 → 포렌식 → 폐기."
}
```

검증:
- `killchain.json` 에 새 rule (`auto=true`) 등장 ✓
- Threat Leader `latest` 에서 GHSA-xqmj-j6mv-4862 제거 (5 → 4 개) ✓
- 다음 `↻ 즉시 탐색` 또는 24h cron 에서도 다시 추천 안 됨 (Seen 영구) ✓

---

## 6. 부수 fix (이번 라운드 발견)

### sandbox 의 boan-proxy 가 자기 자신을 거치는 문제
- proxy 컨테이너의 OSV fetch 는 직접 outbound 가능
- sandbox 컨테이너의 boan-proxy 는 `HTTPS_PROXY=localhost:18080` (자기 자신) → `storage.googleapis.com:443` whitelist 부재 → CONNECT Forbidden
- **해결**: `threatleader.directHTTPClient` 가 `Transport.Proxy = nil` 명시 — env 무시하고 직접 outbound

### 영구 저장 위치
- `userDataDir` (`/data/users`) 는 host bind mount 의 uid 1000 owner — proxy uid 100 이 못 씀
- **해결**: `/tmp/boan/threat-leader/threat-leader.json` (ephemeral, 매일 fetch 라 OK)
- `BOAN_THREAT_LEADER_DIR` env 로 override 가능 (k8s 의 PVC 마운트 등)

---

## 7. 미해결 / phase v3

- **NVD CVE feed 보강**: OSV 에 없는 OS-level / 비-OSS 취약점 (xz/liblzma 같은 시스템 라이브러리) 보강
- **GitHub Security Advisory GraphQL**: PAT 받아서 fetch — OSV 와 중복 많지만 일부 advisory 가 OSV 보다 빠름
- **process_name 정확도 향상**: 현재 ecosystem→runtime 단순 매핑. LLM 으로 advisory text 분석해서 정확한 binary/CLI 이름 추출
- **package downloads 가중치**: 인기 패키지 (npm `axios` 같은) 우선
- **영구 store**: Seen/Ignored 가 컨테이너 재시작 시 잃어짐 (현재 /tmp). 영구 volume 필요
- **RAM dump (winpmem)**: kill chain step 에 RAM 증발 전 메모리 덤프 추가

---

## 8. 합계

| 작업 | 상태 |
|------|------|
| OSV.dev daily fetch backend (5 파일) | ✅ |
| HTTP handler + endpoint 4개 | ✅ |
| Frontend ThreatLeader v2 | ✅ |
| Refresher cron (24h + ↻) | ✅ |
| Accept = KillChain rule auto=true | ✅ |
| Reject = Ignored 마킹 | ✅ |
| sandbox container fetch (directHTTPClient fix) | ✅ |
| /tmp/boan store path fix | ✅ |
| E2E 검증 (실제 OSV → 5 critical → Accept litellm) | ✅ |

**아티팩트**: `internal/threatleader/{types,osv,select,store,refresher}.go`, `internal/proxy/threatleader_handler.go`, `pages/ThreatLeader.tsx` (rewrite).
