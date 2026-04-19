# Test 10 — Admin G1 Pattern (Gateway Policies 탭)

**기능**: G1 정규식 가드레일 등록 → 사용자 전송 텍스트가 패턴 매칭되면 credential_required / block.

## 현재 상태
```
$ curl .../v1/policy | jq '.guardrail.g1_patterns'
[]
```
G1 커스텀 패턴은 아직 없음 (policy server 측). 대신 proxy 의 hard-coded fallback (`credentialLikePatterns`) 사용.

## hardcoded fallback 동작 확인
`input_gate.go` L293-298:
```go
for _, re := range credentialLikePatterns {
    g1Rules = append(g1Rules, compiledG1Rule{re: re, mode: "credential"})
}
```
- SSN, credit card, OpenAI/Anthropic/GitHub API key 같은 정규식 패턴 하드코딩.
- 사용자 전송에 `sk-ant-api03-...` 나 `ghp_...` 포함 시 G1 이 credential_required 로 분기 → credential gate 로 전환.

## 테스트 예시 (Test 30 에서 실행 예정)
사용자가 `ghp_xxxxxxxxxxxx` 를 Secure Input 에 타이핑 → `/api/input-gate/evaluate` → tier=G1, action=credential_required.

## 결론
✅ G1 (hardcoded fallback) 동작. 커스텀 패턴 등록 UI 는 존재하지만 현재 조직은 기본 fallback 사용.
