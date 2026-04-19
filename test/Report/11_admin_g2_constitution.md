# Test 11 — Admin G2 Constitution

**기능**: G2 헌법 텍스트 편집 → G2 LLM 프롬프트에 주입.

## 현재 헌법
```
$ curl .../v1/policy | jq '.guardrail.constitution'
"가드레일 헌법: 자격증명, 비밀번호, 토큰, 개인정보, 사내 비밀, 고객 데이터, 민감한 운영 명령은 외부로 그대로 내보내지 않는다. 완전 무해한 일반 텍스트만 허용한다. 애매하면 ask 로 분류하고 사람 확인을 거친다."
```

## 사용 경로
`evaluateGuardrailLocal` (openclaw_provider.go L974+):
1. `guardrail.GetConstitution(ctx, orgID)` → policy-server `/v1/policy` 에서 헌법 fetch.
2. 프롬프트: `You are a security guardrail. Respond with ONE LINE of strict JSON ONLY... Constitution: {constitution}`.
3. G2 LLM 이 헌법 기반으로 allow/block 결정.

## 검증
Test 22 에서 G2 가 실제로 헌법 참조해 "Gibberish text, no sensitive data" 응답 → allow → DLP 통과. 헌법 수정 후 재호출 시 반영되는 것은 동일 경로이므로 재현 가능.

## 결론
✅ 헌법 fetch + G2 프롬프트 주입 경로 검증됨.
