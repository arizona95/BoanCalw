#!/usr/bin/env bash
# 테스트: Credential Vault 격리 (CV-1 ~ CV-5)
set -euo pipefail
source "$(dirname "$0")/test-helpers.sh"
echo "═══ Credential Vault 격리 테스트 ═══"

# CV-5: credential-filter 독립 실행
section "CV-5: credential-filter 독립 컨테이너"
CF_STATUS=$(docker ps --format '{{.Names}} {{.Status}}' | grep "credential-filter" || echo "")
if echo "$CF_STATUS" | grep -q "Up"; then
  pass "credential-filter 독립 실행 중"
else
  fail "credential-filter 컨테이너 없음: $CF_STATUS"
fi

# CV-1: sandbox에서 AES 키 접근 불가
section "CV-1: sandbox에서 AES 키 접근 불가"
if docker ps --format '{{.Names}}' | grep -q "$SANDBOX"; then
  KEY_ACCESS=$(sandbox_exec ls /etc/boan-cred/aes.key 2>&1 || echo "denied")
  if echo "$KEY_ACCESS" | grep -qi "no such\|denied\|not found"; then
    pass "/etc/boan-cred/aes.key 접근 불가"
  else
    fail "AES 키 접근 가능: $KEY_ACCESS"
  fi
  DIR_ACCESS=$(sandbox_exec ls /etc/boan-cred/ 2>&1 || echo "denied")
  if echo "$DIR_ACCESS" | grep -qi "no such\|denied\|not found"; then
    pass "/etc/boan-cred/ 디렉토리 없음"
  else
    fail "/etc/boan-cred/ 접근 가능"
  fi
else
  warn "sandbox 없음"
fi

# CV-2: sandbox에서 credential API 접근
section "CV-2: sandbox → credential-filter API"
if docker ps --format '{{.Names}}' | grep -q "$SANDBOX"; then
  HEALTH=$(sandbox_curl "http://boan-credential-filter:8082/healthz" || echo "fail")
  [ "$HEALTH" = "ok" ] && pass "healthz 응답 ok" || fail "healthz 응답: $HEALTH"
else
  warn "sandbox 없음"
fi

# CV-3: credential 등록 + 조회
section "CV-3: credential 등록/조회 (외부 컨테이너 경유)"
if docker ps --format '{{.Names}}' | grep -q "$SANDBOX"; then
  # 등록
  REG_CODE=$(sandbox_exec curl -s -w "\n%{http_code}" -X POST "http://boan-credential-filter:8082/credential/sds-corp" \
    -H "Content-Type: application/json" -d '{"role":"test-vault-key","key":"sk-test-vault-12345","ttl_hours":1}' 2>/dev/null | tail -1)
  [ "$REG_CODE" = "201" ] && pass "등록 HTTP 201" || fail "등록 HTTP $REG_CODE"

  # 조회
  GET_RESP=$(sandbox_curl "http://boan-credential-filter:8082/credential/sds-corp/test-vault-key" || echo "{}")
  HAS_KEY=$(echo "$GET_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print('yes' if d.get('key') else 'no')" 2>/dev/null || echo "no")
  [ "$HAS_KEY" = "yes" ] && pass "조회 성공 (복호화된 키 반환)" || fail "조회 실패: $GET_RESP"

  # CV-4: 삭제
  section "CV-4: credential 삭제"
  DEL_CODE=$(sandbox_exec curl -s -w "\n%{http_code}" -X DELETE "http://boan-credential-filter:8082/credential/sds-corp/test-vault-key" 2>/dev/null | tail -1)
  [ "$DEL_CODE" = "204" ] && pass "삭제 HTTP 204" || fail "삭제 HTTP $DEL_CODE"

  # 삭제 후 조회
  AFTER=$(sandbox_curl "http://boan-credential-filter:8082/credential/sds-corp/test-vault-key" || echo '{}')
  STATUS=$(echo "$AFTER" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status',''))" 2>/dev/null)
  [ "$STATUS" = "missing" ] && pass "삭제 후 missing 확인" || fail "삭제 후 상태: $STATUS"

  # CV-6: admin proxy 경유 credential revoke (회귀 방지)
  # 과거 버그: admin.go 의 DELETE 핸들러가 TrimPrefix 오용으로 /v1/passthrough/
  # 분기에 잘못 들어가서 204 는 반환하지만 실제 삭제가 안 됐음.
  section "CV-6: admin proxy 경유 DELETE (회귀 방지)"
  # 다시 등록 (위에서 지웠음)
  sandbox_exec curl -s -X POST "http://boan-credential-filter:8082/credential/sds-corp" \
    -H "Content-Type: application/json" -d '{"role":"test-vault-key-proxy","key":"sk-test-proxy-12345","ttl_hours":1}' > /dev/null 2>&1
  # admin proxy 로 DELETE
  PROXY_DEL=$(sandbox_exec curl -s -w "\n%{http_code}" -X DELETE "http://localhost:18081/api/credential/v1/credentials/test-vault-key-proxy" 2>/dev/null | tail -1)
  [ "$PROXY_DEL" = "204" ] && pass "admin proxy DELETE HTTP 204" || fail "admin proxy DELETE HTTP $PROXY_DEL"
  # list 에서 실제로 사라졌는지 확인 (← 핵심: 과거 버그는 204 리턴만 하고 실제 삭제 X 였음)
  LIST_RAW=$(sandbox_exec curl -s "http://localhost:18081/api/credential/v1/credentials" 2>/dev/null)
  if echo "$LIST_RAW" | grep -q "test-vault-key-proxy"; then
    fail "admin proxy DELETE 후에도 list 에 남아있음 (204 ok 뻥치기 버그 재발)"
  else
    pass "admin proxy DELETE 후 list 에서 사라짐"
  fi
else
  warn "sandbox 없음"
fi

summary
