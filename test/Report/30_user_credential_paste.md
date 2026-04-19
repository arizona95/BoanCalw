# Test 30 — User Credential Paste (Clipboard Gate)

**기능**: 사용자가 로컬에서 GitHub PAT 같은 credential 을 복사 → S1 (remote VM) 에 ctrl+V → credential gate 가 감지해서 block / placeholder 치환.

## 증거 — 실제 PAT 패턴 전송 → G1 block

### text 모드
```
$ curl -b user.txt -X POST /api/input-gate/evaluate \
    -d '{"mode":"text","text":"my key is ghp_thisIsATestTokenWithEnoughLength1234567890abc and some text",...}'
{"allowed":false,
 "action":"block",
 "reason":"[G1] blocked by pattern: \\bghp_[A-Za-z0-9]{20,}\\b",
 "tier":"G1"}
```

### paste 모드
```
$ curl -b user.txt -X POST /api/input-gate/evaluate \
    -d '{"mode":"paste","text":"ghp_testFakePAT123456789abcdef",...}'
{"allowed":false,
 "action":"block",
 "reason":"[G1] blocked by pattern: \\bghp_[A-Za-z0-9]{20,}\\b",
 "tier":"G1"}
```

## 패턴 매칭 경로
- `credentialLikePatterns` (proxy hardcoded) 에 GitHub PAT 정규식 `\bghp_[A-Za-z0-9]{20,}\b` 포함.
- `input_gate.go` L301-327: G1 pattern 매칭 시 `mode=credential` 이면 `credential_required`, `mode=block` 이면 즉시 block.
- 현재 default fallback 은 credential mode. 하지만 여기서 `block` 으로 응답한 걸 보면 이 패턴은 `mode=block` 으로 등록돼있음.

## Clipboard sync 경로
MyGCP.tsx 의 `evaluateClipboardInput` → `inputGateApi.evaluate({mode:"paste",...})` 호출. 해당 응답이 `allowed=false` 면 chat 에 "클립보드 내용이 차단되었습니다" + gateStatus 표시.

## 결론
✅ GitHub PAT 같은 credential pattern clipboard paste 시 G1 에서 **실제로 block**. 사용자가 실수로 raw key 를 remote VM 에 붙여넣기 못 함.
