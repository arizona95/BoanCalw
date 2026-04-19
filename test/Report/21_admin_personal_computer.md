# Test 21 — Admin Personal Computer (Guacamole 원격 접속)

**기능**: Personal Computer 탭 → Guacamole iframe 으로 본인 VM Windows 원격 접속.

---

## 시나리오
1. 사용자 / 관리자 로그인 → Personal Computer 탭 클릭.
2. `/api/workstation/me` 호출 → web_desktop_url 획득.
3. iframe 으로 Guacamole RDP 세션 로드.
4. Windows desktop 표시.

---

## 증거

### 1) /api/workstation/me 응답
```
$ curl -b user.txt /api/workstation/me
{
  "instance_id": "projects/.../boan-win-dowoo-baik",
  "remote_host": "34.47.X.X",
  "remote_port": 3389,
  "remote_user": "boanclaw",
  "remote_pass": "8NhpUxMMuLcjtX$5iN",
  "web_desktop_url": "/remote/#/client/MQBjAHBvc3RncmVzcWw=?token=...",
  "status": "running"
}
```

### 2) iframe 내에 Windows Server 2022 desktop 렌더링
Screenshot 증거: `boan-win-dowoo-baik` VM 에 RDP 성공 후 Server Manager, 작업 표시줄, 바탕화면 표시됨.

### 3) 마우스/키보드 이벤트 forward
MyGCP.tsx overlay (`.absolute.inset-0.z-20`) 가 pointerdown/move 를 `forwardPointerEvent` 로 iframe 내부 canvas 에 dispatch.

### 4) iframe src = Guacamole 세션
`http://localhost:19080/remote/#/client/{connection_id}?token={session_token}` → boan-guacamole container 가 프록시.

---

## 결론
✅ 원격 접속 성공. RDP 세션 로드 + keystroke/mouse forwarding + iframe 렌더링 모두 정상.
