# Test 08 — Admin LLM Register (Vision/Grounding)

**기능**: Vision / Grounding LMM 등록 — computer-use agent 가 사용.

## 증거
- **Vision**: `qwen3-vl:235b-cloud-n8000` (Ollama Cloud 235B) — Test 23 에서 agent NDJSON 이벤트의 `{"type":"status","text":"grounding LMM 사용: boan-grounding-uground-2b"}` / `thinking` 이벤트 (vision 의 OBSERVATION) 로 호출 증명.
- **Grounding**: `boan-grounding-uground-2b` — local vllm GPU 서버. 
  - Test 23 이벤트: `✓ grounding 결과: the address bar... → (302, 58)` — 자연어 → 픽셀 변환 성공.
  - `curl /v1/chat/completions` 으로 text-only + image request 직접 확인 (이전 grounding 디버그 세션).

## 관련 fix (이전 세션)
- vllm multimodal processor 가 `Qwen2VLForConditionalGeneration` resolve 실패로 image 요청 400 에러 → container restart 로 복구.

## 결론
✅ Vision + Grounding LLM 모두 등록 + 실사용 (computer-use agent) 검증.
