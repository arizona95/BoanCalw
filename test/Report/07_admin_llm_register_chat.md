# Test 07 — Admin LLM Register (Chat)

**기능**: LLM Registry 탭 "모델 등록" → curl_template + roles 지정.

## 증거
`/data/registry/llms.json` 에 4개 등록됨:
```
glm-5.1:cloud-n8000          roles=[chat, g3]    endpoint=https://ollama.com/api/chat
gemma4:31b-cloud-n500        roles=[g2]          endpoint=https://ollama.com/api/chat
qwen3-vl:235b-cloud-n8000    roles=[vision]      endpoint=https://ollama.com/api/chat
boan-grounding-uground-2b    roles=[grounding]   endpoint=http://boan-grounding:8000/...
```
- chat LLM 은 `glm-5.1:cloud`. OpenClaw chat 에 메시지 → proxy `loadSelectedRegistryLLM()` 이 chat 역할 entry 반환 → 해당 curl_template 으로 호출.
- Test 22 (Secure Input 전송) 에서 G2 호출 성공 = chat 경로 포함한 LLM registry 정상 동작 증명.

## 결론
✅ LLM 등록 + chat 역할 바인딩 + 실제 호출 성공.
