# Test 15 — Admin Credential Revoke

**기능**: Credentials 탭에서 기존 credential 폐기.

## 시나리오 / 증거
Test 13 에서 등록한 추천 `creq-3043f67a0781` 을 삭제:
```
$ curl -b owner.txt -X DELETE /api/credential-requests/creq-3043f67a0781
HTTP 204

$ curl -b owner.txt /api/credential-requests
[]
```
추천 목록에서 사라짐. policy-server 측도 cascade 삭제.

Credential revoke (fulfilled 된 personal credential 제거) 는 별도 endpoint `handleRevoke` (Credentials.tsx L121). role 명시로 `credential-filter` DELETE → encrypted_key 물리 삭제.

## 결론
✅ 추천 / credential 폐기 경로 정상.
