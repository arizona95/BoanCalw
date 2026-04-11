#!/usr/bin/env bash
# 테스트: Users 관리 (US-1 ~ US-6)
set -euo pipefail
source "$(dirname "$0")/test-helpers.sh"
echo "═══ Users 테스트 ═══"

# US-1: 사용자 목록
section "US-1: 사용자 목록 조회"
RESP=$(curl -sf "$API/api/admin/users" || echo "[]")
COUNT=$(echo "$RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
[ "$COUNT" -gt 0 ] && pass "사용자 ${COUNT}명 조회" || fail "사용자 목록 비어있음"

# access_level 필드 존재
HAS_AL=$(echo "$RESP" | python3 -c "import sys,json; print('yes' if any('access_level' in u for u in json.load(sys.stdin)) else 'no')" 2>/dev/null)
[ "$HAS_AL" = "yes" ] && pass "access_level 필드 존재" || fail "access_level 필드 없음"

# US-2: 권한 변경 (Allow→Deny→Ask)
section "US-2: 권한 변경 (allow/deny/ask)"
TEST_EMAIL=$(echo "$RESP" | python3 -c "import sys,json; [print(u['email']) for u in json.load(sys.stdin) if u.get('role')!='owner'][0:1]" 2>/dev/null || echo "")
if [ -n "$TEST_EMAIL" ]; then
  ORIG=$(echo "$RESP" | python3 -c "import sys,json; [print(u.get('access_level','ask')) for u in json.load(sys.stdin) if u['email']=='$TEST_EMAIL']" 2>/dev/null)
  for LV in allow deny ask; do
    CODE=$(curl -so /dev/null -w '%{http_code}' -X PATCH "$API/api/admin/users" -H "Content-Type: application/json" -d "{\"email\":\"$TEST_EMAIL\",\"access_level\":\"$LV\"}")
    ACTUAL=$(curl -sf "$API/api/admin/users" | python3 -c "import sys,json; [print(u.get('access_level','')) for u in json.load(sys.stdin) if u['email']=='$TEST_EMAIL']" 2>/dev/null)
    [ "$CODE" = "200" ] && [ "$ACTUAL" = "$LV" ] && pass "→ $LV (확인됨)" || fail "→ $LV (HTTP $CODE, 실제=$ACTUAL)"
  done
  # 원복
  curl -sf -X PATCH "$API/api/admin/users" -H "Content-Type: application/json" -d "{\"email\":\"$TEST_EMAIL\",\"access_level\":\"$ORIG\"}" > /dev/null 2>&1
else
  warn "소유자 외 사용자 없음 — 권한 변경 테스트 생략"
fi

# US-3: 잘못된 권한값
section "US-3: 잘못된 access_level 거부"
if [ -n "$TEST_EMAIL" ]; then
  CODE=$(curl -so /dev/null -w '%{http_code}' -X PATCH "$API/api/admin/users" -H "Content-Type: application/json" -d "{\"email\":\"$TEST_EMAIL\",\"access_level\":\"invalid\"}")
  [ "$CODE" = "400" ] && pass "invalid → HTTP 400" || fail "invalid → HTTP $CODE (400 예상)"
fi

# US-6: 소유자 보호 — role/action 변경은 차단 (access_level은 허용)
section "US-6: 소유자 role 변경 차단"
OWNER=$(echo "$RESP" | python3 -c "import sys,json; [print(u['email']) for u in json.load(sys.stdin) if u.get('role')=='owner'][0:1]" 2>/dev/null || echo "")
if [ -n "$OWNER" ]; then
  CODE=$(curl -so /dev/null -w '%{http_code}' -X PATCH "$API/api/admin/users" -H "Content-Type: application/json" -d "{\"email\":\"$OWNER\",\"role\":\"user\"}")
  [ "$CODE" = "403" ] && pass "소유자 role 변경 차단 (403)" || fail "소유자 role 변경 허용됨 (HTTP $CODE)"
fi

summary
