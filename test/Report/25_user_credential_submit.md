# Test 25 — User Credential Submit (추천받은 값 제출)

**기능**: 사용자 Credentials 탭 → 관리자 추천 카드에 값 입력 → Secret Manager 저장.

이 테스트는 Test 13 의 사용자 측. Test 13 에서 `fulfill` endpoint 호출 = 사용자 역할로 진행. 증거 동일.

---

## 증거 (Test 13 에서 사용자 측 확인 요약)

### 사용자 세션으로 추천 fulfill
```
$ curl -b user.txt -X POST /api/credential-requests/{id}/fulfill \
    -d '{"key":"ghp_testFakePAT...","ttl_hours":168}'
{"role":"personal-dowoo.baik-github-pat","status":"fulfilled"}
```

### credential-filter 에 personal role 생성
```
$ curl http://localhost:8082/credential/sds-corp | jq '.[].role'
... "personal-dowoo_baik-github-pat" ...
```

### 로컬에 raw PAT 노출 없음
`grep -r "ghp_testFakePAT" /data` → empty.

---

## 결론
✅ Test 13 과 동일 경로. 사용자 측 제출 정상 동작.
