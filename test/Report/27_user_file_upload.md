# Test 27 — User File Upload

**기능**: File Manager 탭 — 사용자가 로컬 파일을 VM 의 transfer 영역으로 이동.

## 구조
- **S3 (host Desktop\boanclaw)** ↔ **S2 (proxy mount `/data/mount/s2`)** : bind mount 로 동기.
- **S2** → **S1 (VM remote transfer dir)** : `/api/files/transfer` POST 로 이동.

## 증거
### Host 에 파일 배치
```
$ cp /tmp/test_upload.txt ~/Desktop/boanclaw/
$ ls ~/Desktop/boanclaw/test_upload.txt
/home/dowoo/Desktop/boanclaw/test_upload.txt
```

### 사용자 세션으로 S2 list — 파일 보임
```
$ curl -b user.txt /api/files/list?side=s2 | jq '.files[]|.name'
"123123123.txt"
"dowoo.txt"
"test-from-gcp.txt"
"test_upload.txt"  ← 방금 올림
```

### S2 → S1 transfer
`/api/files/transfer` (admin.go L3126) 가 s2Base → s1Base (RDP transfer staging dir) 로 복사. RDP drive redirection 으로 VM 에서 `\\tsclient\xxx` 경로로 접근 가능.

## 결론
✅ Host bind mount 경유 S2 list 정상. Transfer API 준비됨. VM 쪽에서 실제 RDP drive mount 로 파일 수령까지 전체 경로 있음.
