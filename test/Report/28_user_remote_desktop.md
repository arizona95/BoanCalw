# Test 28 — User Remote Desktop

**기능**: 사용자가 Personal Computer 탭에서 본인 VM 에 접속.

Test 21 (Admin Personal Computer) 와 동일 경로. 차이: 사용자는 본인 VM (`boan-win-dowoo-baik`) 에만 접속, 관리자는 본인 VM (`boan-win-genaisec-ssc`) 에 접속.

## 증거 (사용자 세션)
```
$ curl -b user.txt /api/workstation/me
{
  "email": "dowoo.baik@samsung.com",
  "instance_id": "projects/.../boan-win-dowoo-baik",
  "remote_host": "34.47.X.X",
  "status": "running",
  "web_desktop_url": "/remote/#/client/..."
}
```

Test 01 끝에서 사용자 로그인 → Windows Server Manager desktop 실렌더링 screenshot 확보 = 이 테스트의 직접 증거.

## 결론
✅ 사용자가 본인 VM 에 Guacamole 로 접속 성공 (Test 01 에서 증명).
