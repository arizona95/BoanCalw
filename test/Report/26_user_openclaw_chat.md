# Test 26 — User OpenClaw Chat

**기능**: 사용자 BoanClaw 탭 OpenClaw chat 이용.

## 증거
- Test 19 (Admin OpenClaw chat) 과 동일 경로.
- 사용자 세션으로 `/api/chat/inject` / `/api/chat/forward` 호출 가능.
- iframe src `/openclaw/#token=boan-openclaw-local` 로 연결 — session token 공유.

```
$ curl -b user.txt -X POST /api/chat/inject -d '{"role":"user","content":"hi"}'
{"ok":true}
```

Focus 리팩토링 세션에서 iframe.contentDocument 에 pointerdown listener 설치해 user 로그인 상태에서도 사용모드 chat panel 정상 동작 확인됨 (screenshot 포함).

## 결론
✅ 사용자 chat 접근 OK.
