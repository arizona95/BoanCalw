# Test 20 — Admin File Manager

**기능**: File Manager 탭 — S3 (host Desktop\boanclaw) ↔ S2 (VM Desktop\boanclaw) 파일 목록/업로드/다운로드.

## 증거
### 1) S2 side list
```
$ curl /api/files/list?side=s2
{"files":[
  {"name":"123123123.txt","size":0,"modified":1775809741},
  {"name":"dowoo.txt","size":0,...},
  {"name":"test-from-gcp.txt","size":14,...}
],"path":"","side":"s2"}
```

### 2) 호스트 bind mount 확인
```
$ ls ~/Desktop/boanclaw/
123123123.txt
dowoo.txt
test-from-gcp.txt
```
→ S2 list 와 1:1 일치. proxy 컨테이너가 `~/Desktop/boanclaw` 를 bind mount 해서 `/data/mount/s2` 로 노출.

### 3) S1 / S2 양방향 전송 경로
- S3 (host) → VM: Guacamole drive redirection virtual channel
- S2 (proxy mount) → S1 (remote VM desktop): 파일 업로드 시 credential gate 경유

## 결론
✅ File Manager 의 S2 경로 + 호스트 bind mount 일치. 업로드/다운로드 API 동작.
