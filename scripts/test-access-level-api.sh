#!/usr/bin/env bash
# access_level API 통합 테스트 (실행 중인 서비스 대상)
set -euo pipefail

API="http://localhost:19080/api/admin/users"
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
ERRORS=0

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; ERRORS=$((ERRORS+1)); }

echo "═══════════════════════════════════════════════"
echo " Access Level API 통합 테스트"
echo "═══════════════════════════════════════════════"

# ── 1. GET: access_level 필드 존재 확인
echo "▶ [1/4] GET /api/admin/users — access_level 필드 확인"
RESP=$(curl -sf "$API" 2>/dev/null || echo "[]")
if echo "$RESP" | python3 -c "import sys,json; users=json.load(sys.stdin); assert any('access_level' in u for u in users)" 2>/dev/null; then
  pass "access_level 필드 존재"
else
  fail "access_level 필드 없음 (응답: ${RESP:0:200})"
fi

# 소유자가 아닌 첫 번째 사용자 찾기
TEST_EMAIL=$(echo "$RESP" | python3 -c "
import sys, json
users = json.load(sys.stdin)
for u in users:
    if u.get('role') != 'owner':
        print(u['email'])
        break
" 2>/dev/null || echo "")

if [ -z "$TEST_EMAIL" ]; then
  echo "  ⚠ 소유자가 아닌 사용자가 없어서 PATCH 테스트 생략"
  echo "═══════════════════════════════════════════════"
  exit 0
fi
echo "  테스트 대상: $TEST_EMAIL"

# 원래 access_level 저장
ORIG_LEVEL=$(echo "$RESP" | python3 -c "
import sys, json
users = json.load(sys.stdin)
for u in users:
    if u['email'] == '$TEST_EMAIL':
        print(u.get('access_level', 'ask'))
        break
" 2>/dev/null || echo "ask")
echo "  현재 권한: $ORIG_LEVEL"

# ── 2. PATCH: access_level 변경 테스트 (allow → deny → ask)
echo "▶ [2/4] PATCH — access_level 변경"
for LEVEL in allow deny ask; do
  CODE=$(curl -so /dev/null -w '%{http_code}' -X PATCH "$API" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$TEST_EMAIL\",\"access_level\":\"$LEVEL\"}" 2>/dev/null)
  if [ "$CODE" = "200" ]; then
    # 변경 확인
    ACTUAL=$(curl -sf "$API" 2>/dev/null | python3 -c "
import sys, json
for u in json.load(sys.stdin):
    if u['email'] == '$TEST_EMAIL':
        print(u.get('access_level', ''))
        break
" 2>/dev/null)
    if [ "$ACTUAL" = "$LEVEL" ]; then
      pass "→ $LEVEL (HTTP $CODE, 확인됨)"
    else
      fail "→ $LEVEL (HTTP $CODE, 실제값=$ACTUAL)"
    fi
  else
    fail "→ $LEVEL (HTTP $CODE)"
  fi
done

# ── 3. PATCH: 잘못된 access_level 거부 테스트
echo "▶ [3/4] PATCH — 잘못된 access_level 거부"
CODE=$(curl -so /dev/null -w '%{http_code}' -X PATCH "$API" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"access_level\":\"invalid\"}" 2>/dev/null)
if [ "$CODE" = "400" ]; then
  pass "invalid level → HTTP 400 (정상 거부)"
else
  fail "invalid level → HTTP $CODE (400 예상)"
fi

# ── 4. 원래 값 복원
echo "▶ [4/4] 원래 권한 복원 → $ORIG_LEVEL"
curl -sf -X PATCH "$API" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$TEST_EMAIL\",\"access_level\":\"$ORIG_LEVEL\"}" > /dev/null 2>&1
pass "복원 완료"

echo ""
echo "═══════════════════════════════════════════════"
if [ $ERRORS -gt 0 ]; then
  echo -e " ${RED}결과: $ERRORS개 실패${NC}"
  exit 1
else
  echo -e " ${GREEN}결과: 모든 테스트 통과${NC}"
fi
echo "═══════════════════════════════════════════════"
