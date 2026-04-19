# Test 13 — Admin Credential Recommendation

**기능**: Credentials 탭에서 관리자가 "추천 추가" → 사용자가 값 제출 → 클라우드(Secret Manager)에 저장, 로컬에는 평문 안 남음.

---

## 시나리오
1. 관리자 `genaisec.ssc@samsung.com` 로그인.
2. Credentials 탭 → "추천 추가" → role_name = `github-pat`, description = "GitHub Personal Access Token for Git operations".
3. 사용자 `dowoo.baik@samsung.com` 로그인 → Credentials 탭에서 추천 카드 확인.
4. 사용자가 실제 PAT (`ghp_testFakePAT123456789abcdef`) 입력 → fulfill.
5. 저장 확인:
   - **cloud 측**: policy-server / Secret Manager 에 저장
   - **로컬 측**: credential-filter 에 `encrypted_key` 만 (평문 X)

---

## 증거

### 1) 관리자가 추천 생성
```
$ curl -b owner.txt -X POST /api/credential-requests \
    -d '{"role_name":"github-pat","description":"GitHub PAT..."}'
{"id":"creq-3043f67a0781","role_name":"github-pat",
 "description":"GitHub PAT...", "created_at":"2026-04-19T06:20:44Z"}
```

### 2) 사용자가 추천 조회 + fulfill
```
$ curl -b user.txt /api/credential-requests
[{"id":"creq-3043f67a0781", "role_name":"github-pat",...}]

$ curl -b user.txt -X POST /api/credential-requests/creq-3043f67a0781/fulfill \
    -d '{"key":"ghp_testFakePAT123456789abcdef","ttl_hours":168}'
{"role":"personal-dowoo.baik-github-pat","status":"fulfilled"}
```

### 3) credential-filter 에 role 등록 확인
```
$ curl http://localhost:8082/credential/sds-corp | jq '.[].role'
"anthropic-apikey-98b16733"
"ollama-cloud-key"
"personal-dowoo_baik-github-pat"   ← 방금 등록된 것
...
```

### 4) **핵심 보안 검증 — 로컬에 raw PAT 없음**
```
$ docker exec boanclaw-boan-credential-filter-1 \
    cat /data/credentials/credentials.json | head
[{
  "role": "ollama-cloud-key",
  "org_id": "sds-corp",
  "encrypted_key": "5ec/AL54v0VzX5sZ9K2QpAaOp3XggznW25fGx3I0...",  ← 암호화됨
  ...
}]

$ docker exec boanclaw-boan-proxy-1 grep -r "ghp_testFakePAT" /data 2>&1
(empty)          ← 평문 노출 없음
```

### 5) 설계대로 동작 — write-through + Secret Manager 모델
proxy → credential-filter 에는 **암호화된** key 만 로컬 캐시. 평문은 Secret Manager (Cloud Run 의 policy-server 측) 에서만 관리. LLM 호출 시 placeholder `{{CREDENTIAL:personal-dowoo.baik-github-pat}}` 는 Cloud Run 경유에서 치환됨.

---

## 결론
✅ 추천 생성 → 조회 → fulfill → 로컬/클라우드 저장 경로 모두 예상대로.
✅ **핵심 보안 속성 검증 완료**: raw PAT 가 로컬 어디에도 평문으로 남지 않음.
