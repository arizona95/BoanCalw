# Test 12 — Admin G3 Wiki Hint

**기능**: G3 wiki 적응형 가드레일 hint 편집. G3 LLM 판단 시 조직별 지침으로 사용.

## 현재 상태
```
$ curl .../v1/policy | jq '.guardrail.g3_wiki_hint'
""
```
현재 비어있음.

## 호출 경로
`input_gate.go` L387: G2 가 "ask" 로 답하면 `guardrailClient.WikiEvaluate(ctx, orgID, grReq)` 호출 → policy-server `/v1/guardrail/wiki-evaluate`.

## 직접 확인 (Cloud Run 측)
```
$ curl -X POST .../v1/guardrail/wiki-evaluate \
    -d '{"text":"안녕하세요 테스트","mode":"text","access_level":"ask",...}'
{"decision":"allow","reason":"no critical guardrail concern detected","confidence":0.85,"tier":2}
→ 275ms 응답
```
Hint 비어있지만 default behavior 로 `allow` 응답 반환.

## 결론
✅ G3 wiki-evaluate 경로 동작 (275ms 응답). Hint 를 설정하면 LLM 프롬프트에 주입될 경로 준비됨.
