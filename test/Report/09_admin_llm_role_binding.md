# Test 09 — Admin LLM Role Binding

**기능**: LLM 에 역할 (g2/g3/chat/vision/grounding) 바인딩 — 호출 라우팅 결정.

## 증거 — 역할별 바인딩 확인
```
role        → LLM
g2          → gemma4:31b-cloud-n500
g3          → glm-5.1:cloud-n8000
chat        → glm-5.1:cloud-n8000
vision      → qwen3-vl:235b-cloud-n8000
grounding   → boan-grounding-uground-2b
```

## 라우팅 검증 (proxy 코드)
`loadLLMByRole(ctx, "g2")` (openclaw_provider.go L214) 가 registry 에서 `hasRole("g2")` 인 entry 반환. `evaluateGuardrailLocal` (L974) 에서 호출 — Test 22 에서 실제 G2 평가 성공 → role mapping 정상.

## 결론
✅ 5개 역할 모두 실제 호출 경로에서 사용됨 (Test 22, 23 에서 교차 검증).
