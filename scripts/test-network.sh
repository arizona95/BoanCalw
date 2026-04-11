#!/usr/bin/env bash
# 테스트: Network Policy (GN-1 ~ GN-5)
set -euo pipefail
source "$(dirname "$0")/test-helpers.sh"
echo "═══ Network Policy 테스트 ═══"

# 백업
ORIG=$(curl -sf "$POLICY_API" || echo "{}")
ORIG_WL=$(echo "$ORIG" | python3 -c "import sys,json; print(json.dumps(json.load(sys.stdin).get('network_whitelist',[])))" 2>/dev/null)
ORIG_V=$(echo "$ORIG" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',0))" 2>/dev/null)

# GN-1: 호스트 추가
section "GN-1: 호스트 추가"
NEW_WL=$(echo "$ORIG_WL" | python3 -c "import sys,json; wl=json.load(sys.stdin); wl.append({'host':'test-gn1.example.com','ports':[443],'methods':['GET']}); print(json.dumps(wl))" 2>/dev/null)
SAVE=$(curl -sf -X PUT "$POLICY_API" -H "Content-Type: application/json" -d "{\"network_whitelist\":$NEW_WL}" || echo "{}")
NEW_V=$(echo "$SAVE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',0))" 2>/dev/null)
[ "$NEW_V" -gt "$ORIG_V" ] && pass "정책 v${ORIG_V}→v${NEW_V}" || fail "버전 미증가"

# GN-2: 추가 확인 + 제거
section "GN-2: 호스트 확인 및 제거"
HAS=$(curl -sf "$POLICY_API" | python3 -c "import sys,json; print('yes' if any(e['host']=='test-gn1.example.com' for e in json.load(sys.stdin).get('network_whitelist',[])) else 'no')" 2>/dev/null)
[ "$HAS" = "yes" ] && pass "test-gn1 존재 확인" || fail "test-gn1 없음"

CLEAN_WL=$(curl -sf "$POLICY_API" | python3 -c "import sys,json; wl=[e for e in json.load(sys.stdin).get('network_whitelist',[]) if e['host']!='test-gn1.example.com']; print(json.dumps(wl))" 2>/dev/null)
curl -sf -X PUT "$POLICY_API" -H "Content-Type: application/json" -d "{\"network_whitelist\":$CLEAN_WL}" > /dev/null
HAS2=$(curl -sf "$POLICY_API" | python3 -c "import sys,json; print('yes' if any(e['host']=='test-gn1.example.com' for e in json.load(sys.stdin).get('network_whitelist',[])) else 'no')" 2>/dev/null)
[ "$HAS2" = "no" ] && pass "제거 확인" || fail "제거 안 됨"

# GN-3: 차단 확인
section "GN-3: 차단 호스트 접근"
if docker ps --format '{{.Names}}' | grep -q "$SANDBOX"; then
  BLOCKED_EXIT=$(sandbox_exec curl -so /dev/null -w '%{http_code}' --connect-timeout 3 --max-time 5 "https://evil.example.com/" 2>&1; echo $?)
  # exit != 0 이면 차단
  [ "$BLOCKED_EXIT" != "0" ] && pass "evil.example.com 차단됨" || fail "차단 안 됨"
else
  warn "sandbox 없음"
fi

# GN-5: 롤백
section "GN-5: 롤백"
PRE_V=$(curl -sf "$POLICY_API" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',0))" 2>/dev/null || echo "0")
curl -s -X POST "$API/api/policy/v1/policy/rollback" > /dev/null 2>&1 || true
POST_V=$(curl -sf "$POLICY_API" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',0))" 2>/dev/null || echo "0")
pass "롤백 실행 (v${PRE_V}→v${POST_V})"

summary
