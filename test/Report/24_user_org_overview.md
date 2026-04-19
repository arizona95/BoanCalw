# Test 24 — User Org Overview

**기능**: 사용자의 "조직 설정 확인" 탭 — 본인 조직의 정책/설정 readonly 열람.

## 증거
### 1) Policy API (read)
```
$ curl -b user.txt /api/policy/v1/policy
{
  "version": 7,
  "org_id": "sds-corp",
  "network_whitelist": [{"host":"ollama.com","ports":[443],...}],
  "rbac": {"roles":[{"role":"owner","permissions":["policy:read","policy:write",...]}, ...]},
  ...
}
```

### 2) Org Settings API (read)
```
$ curl -b user.txt /api/admin/org-settings
{
  "org_id": "sds-corp",
  "settings": {
    "credential_passthrough": [{"name":"anthropic-fake-manual",...}],
    "golden_image_uri": "projects/.../boan-golden-...",
    ...
  }
}
```

사용자 세션으로도 read 권한. Write 는 owner 만 (rbac.user.permissions = `["workspace:use"]` 뿐).

## 결론
✅ 사용자가 조직 정책 / 설정 조회 가능. RBAC 상 read-only.
