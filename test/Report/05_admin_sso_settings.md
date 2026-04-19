# Test 05 — Admin SSO Settings

**기능**: Authorization > SSO 탭. 조직 로그인 방식 (OTP/OAuth) 설정.

## 증거
- Env `BOAN_ALLOWED_SSO=email_otp` → 현재 OTP 방식만 허용.
- `/api/auth/config` 응답: `{"allowed_email_domains":["samsung.com","samsungsds.com"], "sso_providers":[], "test_mode":true}`.
- policy-server `/v1/policy`: 도메인 whitelist 정상.
- 로그인 시 samsung.com 외 이메일 → 403 "허용된 회사 이메일만 사용할 수 있습니다" 응답 (Test 이전 검증).

## 결론
✅ SSO 설정 현재 OTP 전용 + 도메인 whitelist 동작.
