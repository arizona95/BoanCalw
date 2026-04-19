# Test 17 — Admin Observability Trace

**기능**: Observability 탭에서 모든 input-gate / LLM / guardrail 이벤트 조회.

## 증거
```
$ curl /api/observability/traces
{
  "total": 3,
  "traces": [
    {
      "timestamp": "2026-04-19T06:42:02...",
      "type": "chat",
      "direction": "inbound",
      "summary": "Current time: ...",
      "decision": "allow",
      "gate": "G1"
    },
    {
      "timestamp": "2026-04-19T06:19:39...",
      "type": "guardrail",
      "direction": "outbound",
      "source": "dowoo.baik@samsung.com",
      "target": "gcp",
      "summary": "아무거나",
      "decision": "block",
      "gate": "access",
      "meta": {"access_level": "deny", ...}
    },
    ...
  ]
}
```

## 검증
- Test 04 에서 access_level=deny 로 전송 → 여기 trace 에 `decision=block, gate=access` 로 실제 기록됨.
- 사용자 이메일 + target + reason + meta 까지 풀 메타데이터 저장.
- `addTrace` (admin.go L165) 가 input-gate handler 와 chat handler 양쪽에서 호출됨.

## 결론
✅ trace 실시간 기록 동작. Test 04 의 deny block 이 실제로 observability trace 에 남음.
