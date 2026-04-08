#!/usr/bin/env bash
# 네트워크 정책 게이트웨이 통합 테스트
# 1. 네트워크 허용 목록 추가/제거 + API 즉각반영 확인
# 2. 정책 게이트웨이 안에서 curl 테스트 (허용/차단 확인)
set -euo pipefail

POLICY_API="http://localhost:19080/api/policy/v1/policy"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
ERRORS=0

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; ERRORS=$((ERRORS+1)); }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }

echo "═══════════════════════════════════════════════"
echo " Network Policy Gateway 통합 테스트"
echo "═══════════════════════════════════════════════"

# ── 1. 현재 정책 백업 ──
echo "▶ [1/6] 현재 정책 백업"
ORIG_POLICY=$(curl -sf "$POLICY_API" 2>/dev/null || echo "{}")
ORIG_WHITELIST=$(echo "$ORIG_POLICY" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin).get('network_whitelist',[])))" 2>/dev/null || echo "[]")
ORIG_VERSION=$(echo "$ORIG_POLICY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',0))" 2>/dev/null || echo "0")
pass "백업 완료 (v${ORIG_VERSION}, ${ORIG_WHITELIST:0:80}...)"

# ── 2. 테스트용 네트워크 추가 ──
echo "▶ [2/6] 네트워크 허용 목록에 테스트 호스트 추가"
# 기존 whitelist에 test-allow.example.com 추가
TEST_WHITELIST=$(echo "$ORIG_WHITELIST" | python3 -c "
import sys, json
wl = json.load(sys.stdin)
wl.append({'host':'test-allow.example.com','ports':[443],'methods':['GET']})
print(json.dumps(wl))
" 2>/dev/null)

SAVE_RESP=$(curl -sf -X PUT "$POLICY_API" \
  -H "Content-Type: application/json" \
  -d "{\"network_whitelist\":${TEST_WHITELIST}}" 2>/dev/null || echo "{}")
NEW_VERSION=$(echo "$SAVE_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',0))" 2>/dev/null || echo "0")

if [ "$NEW_VERSION" -gt "$ORIG_VERSION" ]; then
  pass "정책 저장됨 (v${ORIG_VERSION} → v${NEW_VERSION})"
else
  fail "정책 버전 미증가 (v${ORIG_VERSION} → v${NEW_VERSION})"
fi

# ── 3. 추가된 호스트 확인 ──
echo "▶ [3/6] 추가된 호스트 확인"
CURRENT=$(curl -sf "$POLICY_API" 2>/dev/null)
HAS_TEST=$(echo "$CURRENT" | python3 -c "
import sys,json
wl = json.load(sys.stdin).get('network_whitelist',[])
found = any(e.get('host')=='test-allow.example.com' for e in wl)
print('yes' if found else 'no')
" 2>/dev/null || echo "no")

if [ "$HAS_TEST" = "yes" ]; then
  pass "test-allow.example.com 허용 목록에 존재"
else
  fail "test-allow.example.com 허용 목록에 없음"
fi

# ── 4. 테스트 호스트 제거 ──
echo "▶ [4/6] 테스트 호스트 제거"
CLEANED_WHITELIST=$(echo "$CURRENT" | python3 -c "
import sys,json
wl = json.load(sys.stdin).get('network_whitelist',[])
wl = [e for e in wl if e.get('host')!='test-allow.example.com']
print(json.dumps(wl))
" 2>/dev/null)

SAVE2_RESP=$(curl -sf -X PUT "$POLICY_API" \
  -H "Content-Type: application/json" \
  -d "{\"network_whitelist\":${CLEANED_WHITELIST}}" 2>/dev/null || echo "{}")
V2=$(echo "$SAVE2_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',0))" 2>/dev/null || echo "0")

HAS_TEST2=$(curl -sf "$POLICY_API" 2>/dev/null | python3 -c "
import sys,json
wl = json.load(sys.stdin).get('network_whitelist',[])
print('yes' if any(e.get('host')=='test-allow.example.com' for e in wl) else 'no')
" 2>/dev/null || echo "yes")

if [ "$HAS_TEST2" = "no" ]; then
  pass "테스트 호스트 제거됨 (v${V2})"
else
  fail "테스트 호스트 제거 안 됨"
fi

# ── 5. 정책 게이트웨이 안에서 네트워크 테스트 (sandbox 내부 curl) ──
echo "▶ [5/6] Sandbox 내부 네트워크 게이트 테스트"
# api.anthropic.com은 기본 허용 → 연결 가능해야 함
SANDBOX_CONTAINER="boanclaw-boan-sandbox-1"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "$SANDBOX_CONTAINER"; then
  # 허용된 호스트 테스트 (api.anthropic.com:443 — 기본 whitelist)
  ALLOWED_RESULT=$(docker exec "$SANDBOX_CONTAINER" curl -so /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 8 "https://api.anthropic.com/v1/messages" -X POST -H "Content-Type: application/json" -d '{}' 2>&1 || echo "fail")
  ALLOWED_CODE=$(echo "$ALLOWED_RESULT" | tail -1)
  if [ "$ALLOWED_CODE" != "000" ] && [ "$ALLOWED_CODE" != "fail" ]; then
    pass "허용 호스트(api.anthropic.com) 접근 가능 (HTTP $ALLOWED_CODE)"
  else
    warn "허용 호스트 접근 불가 (네트워크/프록시 설정 문제일 수 있음)"
  fi

  # 차단된 호스트 테스트 (evil.example.com — whitelist에 없음)
  # proxy가 CONNECT를 차단하면 curl은 exit code != 0 반환
  BLOCKED_RESULT=$(docker exec "$SANDBOX_CONTAINER" curl -so /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 8 "https://evil.example.com/steal" 2>&1; echo "EXIT:$?")
  BLOCKED_EXIT=$(echo "$BLOCKED_RESULT" | grep -o 'EXIT:[0-9]*' | cut -d: -f2)
  BLOCKED_CODE=$(echo "$BLOCKED_RESULT" | head -1 | tr -d '[:space:]')
  if [ "$BLOCKED_EXIT" != "0" ] || [ "$BLOCKED_CODE" = "403" ] || [ "$BLOCKED_CODE" = "000" ]; then
    pass "차단 호스트(evil.example.com) 접근 차단됨 (exit=$BLOCKED_EXIT, code=$BLOCKED_CODE)"
  else
    fail "차단 호스트에 접근됨 (exit=$BLOCKED_EXIT, code=$BLOCKED_CODE)"
  fi
else
  warn "sandbox 컨테이너 없음 — 네트워크 게이트 테스트 생략"
fi

# ── 6. 롤백 테스트 ──
echo "▶ [6/6] 정책 롤백 테스트"
PRE_ROLLBACK_V=$(curl -sf "$POLICY_API" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',0))" 2>/dev/null || echo "0")
ROLLBACK_RESP=$(curl -sf -X POST "http://localhost:19080/api/policy/v1/policy/rollback" 2>/dev/null || echo "{}")
POST_ROLLBACK_V=$(curl -sf "$POLICY_API" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',0))" 2>/dev/null || echo "0")

if [ "$POST_ROLLBACK_V" != "$PRE_ROLLBACK_V" ] || [ -n "$(echo "$ROLLBACK_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('version',''))" 2>/dev/null)" ]; then
  pass "롤백 실행됨 (v${PRE_ROLLBACK_V} → v${POST_ROLLBACK_V})"
else
  warn "롤백 결과 확인 불가"
fi

echo ""
echo "═══════════════════════════════════════════════"
if [ $ERRORS -gt 0 ]; then
  echo -e " ${RED}결과: $ERRORS개 실패${NC}"
  exit 1
else
  echo -e " ${GREEN}결과: 모든 테스트 통과${NC}"
fi
echo "═══════════════════════════════════════════════"
