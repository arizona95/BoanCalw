# Test 04 — Admin User Access Level (Allow/Ask/Deny)

**기능**: Users 탭의 access_level 드롭다운. 사용자별 권한 레벨.
- **Allow**: G1 통과 후 G2/G3 스킵, DLP 만 → 매우 빠름
- **Ask** (default): G1 → G2 LLM → G3 wiki → DLP 전부 평가 → 느림
- **Deny**: 하향 데이터 전송 전면 차단

---

## 시나리오
관리자가 사용자 access_level 을 바꾸면 /api/input-gate/evaluate 동작이 레벨별로 달라진다.

---

## 증거 (실제 API 호출 타이밍)

### Allow (`dowoo.baik` → allow 변경 후 전송)
```
$ time curl -s -b user.txt -X POST .../api/input-gate/evaluate \
    -d '{"mode":"text","text":"테스트 메시지",...}'
{"allowed":true,"action":"allow","reason":"[DLP] passed all tiers","tier":"DLP",...}

real    0m0.057s      ← 57ms
```
→ 응답 57ms. G2 LLM 호출 없음 (이전 Ask 모드 45초 대비 789x 빠름).

### Deny (`dowoo.baik` → deny 변경 후 전송)
```
$ curl -s -b user.txt -X POST .../api/input-gate/evaluate \
    -d '{"mode":"text","text":"아무거나",...}'
{"allowed":false,"action":"block","reason":"[access_level=deny] 사용자는 하향 데이터 전송이 금지됩니다","tier":"access"}
```
→ tier="access" 로 즉시 block. G2 호출조차 안 함.

### Ask (기본값)
이전 테스트에서 45초 소요 (G2 cold start) / 후속 3-10초. tier="DLP" 로 통과되지만 G2 LLM 실제 호출 proxy 로그에서 확인.

---

## 검증된 동작 매트릭스

| access_level | G1 | G2 | G3 | DLP | 예상 latency | 테스트 결과 |
|---|---|---|---|---|---|---|
| Allow | ✓ | skip | skip | ✓ | <100ms | 57ms ✓ |
| Ask | ✓ | ✓ | ✓ (ask 시만) | ✓ | 3-45s | 3s~45s 확인 |
| Deny | skip | skip | skip | skip | <10ms | 즉시 block ✓ |

---

## 결론
✅ 세 레벨 모두 의도대로 동작. `input_gate.go` L337-374 의 분기 로직이 정확히 반영됨:
- `access_level == "deny"` & downward → 즉시 block
- `access_level != "allow"` → G2/G3 경유
- `access_level == "allow"` → G1 + DLP 만 실행

API latency 차이로 동작 차이 직접 증명됨.
