#!/usr/bin/env bash
# computer-use 기본 동작 디버깅 스크립트
# 사용법: scripts/test-computer-use.sh [guacamole-session-url]
set -euo pipefail

COMPUTER_USE_URL="${1:-http://localhost:8090}"
PROXY_ADMIN_URL="http://localhost:18081"
CONSOLE_URL="http://localhost:19080"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; ERRORS=$((ERRORS+1)); }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }

ERRORS=0

echo "═══════════════════════════════════════════════"
echo " BoanClaw Computer-Use 디버깅 테스트"
echo "═══════════════════════════════════════════════"
echo ""

# ── 1. 서비스 헬스체크 ─────────────────────────────────────────
echo "▶ [1/5] 서비스 상태 확인"

# admin-console
if curl -sf "$CONSOLE_URL/" > /dev/null 2>&1; then
  pass "admin-console ($CONSOLE_URL)"
else
  fail "admin-console ($CONSOLE_URL) — 502 Bad Gateway 원인일 수 있음"
fi

# computer-use
if curl -sf "$COMPUTER_USE_URL/healthz" > /dev/null 2>&1; then
  pass "computer-use ($COMPUTER_USE_URL/healthz)"
else
  fail "computer-use ($COMPUTER_USE_URL/healthz)"
fi

# proxy admin
if curl -sf "$PROXY_ADMIN_URL/" > /dev/null 2>&1; then
  pass "proxy-admin ($PROXY_ADMIN_URL)"
else
  # proxy admin은 404여도 연결 자체는 되면 OK
  HTTP_CODE=$(curl -so /dev/null -w '%{http_code}' "$PROXY_ADMIN_URL/" 2>/dev/null || echo "000")
  if [ "$HTTP_CODE" != "000" ]; then
    pass "proxy-admin ($PROXY_ADMIN_URL) — HTTP $HTTP_CODE"
  else
    fail "proxy-admin ($PROXY_ADMIN_URL) — 연결 불가"
  fi
fi

# sandbox (openclaw)
SANDBOX_CODE=$(curl -so /dev/null -w '%{http_code}' "http://localhost:18789/" 2>/dev/null || echo "000")
if [ "$SANDBOX_CODE" != "000" ]; then
  pass "sandbox (:18789) — HTTP $SANDBOX_CODE"
else
  fail "sandbox (:18789) — 연결 불가"
fi

echo ""

# ── 2. Docker 컨테이너 상태 ────────────────────────────────────
echo "▶ [2/5] Docker 컨테이너 상태"

for svc in boan-proxy boan-sandbox boan-admin-console boan-computer-use; do
  CNAME="boanclaw-${svc}-1"
  STATUS=$(docker inspect --format '{{.State.Status}}' "$CNAME" 2>/dev/null || echo "not found")
  CREATED=$(docker inspect --format '{{.Created}}' "$CNAME" 2>/dev/null | cut -d'T' -f2 | cut -d'.' -f1 || echo "?")
  HEALTH=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}}' "$CNAME" 2>/dev/null || echo "?")
  if [ "$STATUS" = "running" ]; then
    pass "$svc — $STATUS (health=$HEALTH, started=$CREATED UTC)"
  else
    fail "$svc — $STATUS"
  fi
done

echo ""

# ── 3. computer-use API 직접 테스트 ─────────────────────────────
echo "▶ [3/5] computer-use API 직접 호출 테스트"

# 스크린샷 테스트 (Guacamole URL이 있어야 실제 동작)
# Guacamole URL 없이도 API 자체가 응답하는지 확인
RESP=$(curl -s -X POST "$COMPUTER_USE_URL/screenshot" \
  -H "Content-Type: application/json" \
  -d '{"web_desktop_url":"http://boan-guacamole:8080/guacamole/#/client/test"}' \
  -w "\n%{http_code}" 2>/dev/null || echo -e "\n000")
HTTP_CODE=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | head -n -1)

if [ "$HTTP_CODE" = "200" ]; then
  # 이미지 데이터가 있는지 확인
  IMG_LEN=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('image','')))" 2>/dev/null || echo "0")
  if [ "$IMG_LEN" -gt 100 ]; then
    pass "screenshot API — 200 OK (image=${IMG_LEN} chars)"
  else
    warn "screenshot API — 200 but image empty/short (${IMG_LEN} chars)"
  fi
elif [ "$HTTP_CODE" = "500" ]; then
  warn "screenshot API — 500 (Guacamole 세션 없으면 정상): $(echo "$BODY" | head -c 120)"
else
  fail "screenshot API — HTTP $HTTP_CODE"
fi

# click 테스트 (세션 없으면 500이 정상)
CLICK_CODE=$(curl -so /dev/null -w '%{http_code}' -X POST "$COMPUTER_USE_URL/click" \
  -H "Content-Type: application/json" \
  -d '{"web_desktop_url":"http://boan-guacamole:8080/guacamole/#/client/test","x":100,"y":100}' 2>/dev/null || echo "000")
if [ "$CLICK_CODE" = "200" ]; then
  pass "click API — 200 OK"
elif [ "$CLICK_CODE" = "500" ]; then
  warn "click API — 500 (Guacamole 세션 없으면 정상)"
else
  fail "click API — HTTP $CLICK_CODE"
fi

# key 테스트
KEY_CODE=$(curl -so /dev/null -w '%{http_code}' -X POST "$COMPUTER_USE_URL/key" \
  -H "Content-Type: application/json" \
  -d '{"web_desktop_url":"http://boan-guacamole:8080/guacamole/#/client/test","name":"Escape"}' 2>/dev/null || echo "000")
if [ "$KEY_CODE" = "200" ]; then
  pass "key API — 200 OK"
elif [ "$KEY_CODE" = "500" ]; then
  warn "key API — 500 (Guacamole 세션 없으면 정상)"
else
  fail "key API — HTTP $KEY_CODE"
fi

echo ""

# ── 4. computer-use 큐 폴링 경로 확인 ──────────────────────────
echo "▶ [4/5] computer-use 큐 폴링 경로 (proxy admin)"

# /api/computer-use/poll 은 proxy admin (sandbox 내부 18081)에서 서빙
# 외부에서는 admin-console의 nginx를 통해 접근
POLL_CODE=$(curl -so /dev/null -w '%{http_code}' "$CONSOLE_URL/api/computer-use/poll" -m 3 2>/dev/null || echo "000")
if [ "$POLL_CODE" = "200" ] || [ "$POLL_CODE" = "204" ] || [ "$POLL_CODE" = "404" ]; then
  pass "poll endpoint via console — HTTP $POLL_CODE"
elif [ "$POLL_CODE" = "502" ]; then
  fail "poll endpoint — 502 (sandbox/proxy 연결 끊김)"
elif [ "$POLL_CODE" = "000" ]; then
  warn "poll endpoint — timeout (큐가 비어있으면 정상, 5s long-poll)"
else
  warn "poll endpoint — HTTP $POLL_CODE"
fi

echo ""

# ── 5. 최근 로그 요약 ──────────────────────────────────────────
echo "▶ [5/5] 최근 computer-use 관련 로그"

echo "  --- boan-proxy (최근 agent 로그) ---"
docker logs boanclaw-boan-proxy-1 2>&1 | grep -i "computer-use" | tail -5 || echo "  (없음)"
echo ""
echo "  --- boan-sandbox (최근 agent 로그) ---"
docker logs boanclaw-boan-sandbox-1 2>&1 | grep -i "computer-use\|step=" | tail -5 || echo "  (없음)"
echo ""
echo "  --- boan-computer-use (최근 에러) ---"
docker logs boanclaw-boan-computer-use-1 2>&1 | grep -iE "error|fail|exception" | tail -5 || echo "  (없음)"

echo ""
echo "═══════════════════════════════════════════════"
if [ $ERRORS -gt 0 ]; then
  echo -e " ${RED}결과: $ERRORS개 실패${NC}"
  exit 1
else
  echo -e " ${GREEN}결과: 모든 기본 검사 통과${NC}"
fi
echo "═══════════════════════════════════════════════"
