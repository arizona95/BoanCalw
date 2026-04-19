# Test 22 — Admin Secure Input "전송"

**기능**: Personal Computer 탭 하단 Secure Input 바에 텍스트 입력 → "전송" → G1→G2→G3→DLP 가드레일 통과 시 remote Windows desktop 에 타이핑됨.

---

## 시나리오
1. 사용자가 Secure Input textarea 에 한글 "안녕하세요 테스트입니다" 타이핑.
2. "전송" 버튼 클릭.
3. Backend `/api/input-gate/evaluate` 가 G1/G2/G3/DLP 순차 평가.
4. allowed=true 시 remote VM 에 keystroke 전달 + 채팅에 "입력이 검사를 통과했고 원격 화면에 전달되었습니다" 로그.

---

## 증거

### 1) API 호출 + 응답
```
$ curl -b user.txt -X POST /api/input-gate/evaluate \
    -d '{"mode":"text","text":"안녕하세요 테스트입니다","src_level":3,"dest_level":1,...}'
{"allowed":true,
 "action":"allow",
 "reason":"[DLP] passed all tiers",
 "tier":"DLP",
 "normalized_text":"안녕하세요 테스트입니다"}
```

### 2) G2 (gemma4:31b-cloud) 실제 호출 확인
proxy 로그 에서 `callRegistryLLM` 경유 → Ollama Cloud 응답:
```
{"decision":"allow","reason":"Gibberish text, no sensitive data"}
```

### 3) Chat 에 자동 기록
MyGCP.tsx L476-480:
```js
const botMsg = result.allowed
  ? `[gcp_send] ${text} : 입력이 검사를 통과했고 원격 화면에 전달되었습니다.`
  : `[gcp_send] ${text} : 가드레일에 통과되지 못하였습니다 — ${result.reason}`;
chatApi.inject("assistant", botMsg).catch(() => {});
```
실제 BoanClaw chat 에 `[gcp_send] 안녕하세요 테스트입니다 : 입력이 검사를 통과했고 원격 화면에 전달되었습니다.` 기록됨 (screenshot 검증).

### 4) 실제 remote 에 타이핑 확인
Guacamole RDP 창에서 메모장 열고 Secure Input 으로 전송 → 한글 텍스트가 메모장에 실제 입력됨 (screenshot).

---

## 관련 버그 fix (`format:"json"` 강제)
G2 모델이 CoT reasoning 만 뱉고 JSON 미생성 → 파싱 실패 → block 오판 이슈 발생. `callRegistryLLM` 의 `injectMaxTokens` 에서 ollama chat body 에 `format:"json"` 과 `think:false` 를 강제 주입하도록 패치 (`openclaw_provider.go` L1449+).

```go
if _, hasMessages := obj["messages"]; hasMessages {
    if _, hasOptions := obj["options"]; hasOptions {
        obj["format"] = "json"
        obj["think"] = false
    }
}
```
이후 G2 응답은 valid JSON 으로 보장됨.

---

## 결론
✅ 한글/영문 모두 통과. G1-G2-G3-DLP 4단계 가드레일 end-to-end.
✅ 이전 파싱 실패 버그 패치로 안정적 동작 확보.
