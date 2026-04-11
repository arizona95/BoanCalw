#!/usr/bin/env bash
# 테스트 공통 헬퍼
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
ERRORS=0; PASSED=0; TOTAL=0

pass() { PASSED=$((PASSED+1)); TOTAL=$((TOTAL+1)); echo -e "  ${GREEN}✓${NC} $1"; }
fail() { ERRORS=$((ERRORS+1)); TOTAL=$((TOTAL+1)); echo -e "  ${RED}✗${NC} $1"; }
warn() { TOTAL=$((TOTAL+1)); echo -e "  ${YELLOW}⚠${NC} $1"; }
section() { echo ""; echo "▶ $1"; }

summary() {
  echo ""
  echo "═══════════════════════════════════════════════"
  if [ $ERRORS -gt 0 ]; then
    echo -e " ${RED}결과: ${PASSED}/${TOTAL} 통과, ${ERRORS}개 실패${NC}"
  else
    echo -e " ${GREEN}결과: ${TOTAL}/${TOTAL} 모두 통과${NC}"
  fi
  echo "═══════════════════════════════════════════════"
  return $ERRORS
}

API="http://localhost:19080"
POLICY_API="$API/api/policy/v1/policy"
SANDBOX="boanclaw-boan-sandbox-1"

sandbox_exec() { docker exec "$SANDBOX" "$@" 2>/dev/null; }
sandbox_curl() { sandbox_exec curl -sf "$@" 2>/dev/null; }
