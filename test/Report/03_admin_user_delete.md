# Test 03 — Admin User Delete

**기능**: Users 탭 "삭제" 버튼. 사용자 계정 제거 + VM 즉시 삭제 + policy-server 에서 제거.

---

## 시나리오
1. Users 탭에서 삭제할 사용자 "삭제" 클릭.
2. Confirm 다이얼로그 확인.
3. Backend `/api/admin/users` DELETE:
   - (a) GCP compute instance DELETE (best-effort)
   - (b) policy-server DeleteUser API 호출
   - (c) 로컬 users.json 에서 제거
4. 삭제 후 해당 이메일로 재가입 / 다른 사용자가 같은 PC 에서 가입 가능.

---

## 증거

### 1) 삭제 전 VM 존재
```
$ gcloud compute instances describe boan-win-dowoo-baik1 --zone=... \
    --format='value(status)'
RUNNING
```

### 2) 삭제 클릭 후 VM 제거 확인
```
$ gcloud compute instances describe boan-win-dowoo-baik1 --zone=... \
    --format='value(status)'
ERROR: (gcloud.compute.instances.describe) Could not fetch resource:
 - The resource 'projects/.../instances/boan-win-dowoo-baik1' was not found
```
→ VM 이 GCP 에서 완전히 제거됨 (status=STOPPING → terminated → 삭제).

### 3) policy-server 에서도 제거
```
$ curl -H "Authorization: Bearer $TOKEN" \
    .../org/sds-corp/v1/users | jq '.[].email'
"genaisec.ssc@samsung.com"
# dowoo.baik1 사라짐
```

### 4) 로컬 users.json 에서 제거
```
$ docker exec -u root boanclaw-boan-proxy-1 cat /data/users/users.json | jq 'length'
2  → 1
```

### 5) TOFU 1-PC 바인딩 해제 효과
이전: `dowoo.baik` 이 해당 PC IP 해시 `650f9e2d...` 에 바인딩돼서 `dowoo.baik1` 로그인 시도 → 403 "이 PC는 이미 다른 사용자 계정에 연결".
삭제 후: `dowoo.baik` 재가입 → 해당 IP 에 바인딩 재획득 → 로그인 정상 통과.

---

## 결론
✅ 삭제 UI 클릭 → GCP / policy-server / local DB 모두에서 제거됨. cascade 정상. 다음 사용자 등록 가능.
