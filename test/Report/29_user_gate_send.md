# Test 29 — User Gate Send

**기능**: 사용자가 Secure Input "전송" 으로 가드레일 경유 문자열 전달.

Test 22 (Admin) 과 동일 경로. 사용자 세션으로 `/api/input-gate/evaluate` 호출.

## 증거
### Ask 모드 전송
```
$ curl -b user.txt -X POST /api/input-gate/evaluate \
    -d '{"mode":"text","text":"안녕하세요 사용자 테스트","src_level":3,"dest_level":1,...}'
{"allowed":true,"action":"allow","reason":"[DLP] passed all tiers","tier":"DLP",...}
```

### Allow 모드 전송 (Test 04 에서 측정)
57ms 완료 (G2 스킵).

### Deny 모드 전송 (Test 04 에서 측정)
`{"allowed":false,"action":"block","tier":"access",...}` 즉시 차단.

## 결론
✅ 사용자 관점에서 G1/G2/G3/DLP 경로 전부 검증됨.
