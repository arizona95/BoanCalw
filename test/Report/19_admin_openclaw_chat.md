# Test 19 — Admin OpenClaw Chat (BoanClaw 탭)

**기능**: BoanClaw/OpenClaw 채팅 iframe 에서 관리자가 chat 사용.

## 증거
### 1) OpenClaw iframe reachable
```
$ curl http://localhost:19080/openclaw/ -o /dev/null -w "%{http_code}\n"
200
```

### 2) Chat inject API 정상
```
$ curl -X POST /api/chat/inject -d '{"role":"user","content":"test-inject-from-curl"}'
{"ok":true}  HTTP 200
```

### 3) Chat forward (LLM 호출) endpoint
`/api/chat/forward` (admin.go L4622) 가 chat 메시지 → chat LLM (`glm-5.1:cloud`) 호출. Test 17 trace 에 `type=chat, source=sds-corp, target=llm, decision=allow, gate=G1` 로 기록됨.

### 4) OpenClaw iframe 과 상호작용
- 이전 세션 screenshot 에서 OpenClaw chat 패널 "Ready to chat" 상태 + "Message Assistant (Enter to send)" textarea 확인.
- iframe.contentDocument 에 pointerdown listener 설치해서 focus 전환 이벤트 수신 (Test 는 focus 리팩토링 세션 에서 완료).

## 결론
✅ OpenClaw 연결 + chat inject + forward + focus 전환 전부 동작.
