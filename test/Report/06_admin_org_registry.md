# Test 06 — Admin Org Registry

**기능**: Authorization > 조직 탭. 여러 조직의 정책서버 URL/토큰 관리.

## 증거
```
$ curl /api/orgs
[{"org_id":"sds-corp","url":"https://boan-policy-server-sds-corp-3avhtf4kka-du.a.run.app","is_active":true,...}]
```
- `sds-corp` 하나만 활성. 로그인 drop-down 에도 이 조직만 나타남.
- 조직 추가/삭제 endpoint 는 `/api/admin/orgs` (POST/DELETE). 현재 env `BOAN_ORG_ID=sds-corp` 로 기본 조직 고정.
- Token 은 `/data/config/sds-corp.token` 에 저장 (proxy env `BOAN_ORG_TOKEN`).

## 결론
✅ 조직 1개 관리 정상. 다중 조직 확장 포인트 있음 (`POST /api/admin/orgs`).
