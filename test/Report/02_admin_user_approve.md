# Test 02 — Admin User Approve

**기능**: Users 탭 pending 사용자 옆 "✓ 수락" 버튼. 관리자가 승인하면 policy-server 상태 변경 + VM 자동 프로비저닝.

---

## 시나리오
1. 사용자가 `/register` 페이지에서 가입 요청.
2. policy-server 에 `status=pending` 으로 등록.
3. 관리자 Users 탭에서 pending 사용자 "✓ 수락" 클릭.
4. Backend 가 `/api/admin/users` PATCH → policy-server 상태를 `approved` 로 sync.
5. 관리자가 승인하는 순간 workstation provisioning 트리거 → GCP VM 생성.

---

## 증거

### 1) 가입 요청 → pending 상태 확인
```
$ curl -H "Authorization: Bearer $TOKEN" \
    https://boan-policy-server-sds-corp-3avhtf4kka-du.a.run.app/org/sds-corp/v1/users
[
  {
    "email": "dowoo.baik@samsung.com",
    "status": "pending",
    "auth_provider": "public-register",
    "created_at": "2026-04-19T06:11:22..."
  },
  ...
]
```

### 2) UI 에 pending 표시 — 승인 버튼 보임
Browser snapshot:
```json
{
  "email": "dowoo.baik@samsung.com",
  "buttons": ["✓ 수락", "삭제"]
}
```

### 3) "✓ 수락" 클릭 → status=approved 로 변경
승인 후 재조회:
```json
{
  "email": "dowoo.baik@samsung.com",
  "status": "approved",
  "workstation": {
    "status": "provisioning",
    "instance_id": "projects/.../boan-win-dowoo-baik",
    "assigned_at": "2026-04-19T06:12:..."
  }
}
```

### 4) GCP 에 VM 실제 생성 확인
```
$ gcloud compute instances list --filter='name~boan-win-dowoo-baik'
NAME                  STATUS
boan-win-dowoo-baik   STAGING → RUNNING (약 2분 후)
```

### 5) proxy 의 로컬 users.json 에도 workstation credentials 저장
```
$ docker exec -u root boanclaw-boan-proxy-1 cat /data/users/users.json | jq '.[] | select(.email=="dowoo.baik@samsung.com")'
{
  "email": "dowoo.baik@samsung.com",
  "role": "user",
  "workstation": {
    "status": "running",
    "remote_host": "34.47.X.X",
    "remote_user": "boanclaw",
    "remote_pass": "8NhpUxMMuLcjtX$5iN"
  }
}
```

---

## 결론
✅ 관리자 승인 UI 클릭 → policy-server sync → GCP VM 생성 → credentials 저장까지 end-to-end 동작.
