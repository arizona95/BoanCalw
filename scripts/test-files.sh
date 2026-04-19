#!/usr/bin/env bash
# 테스트: File Manager (FM-1 ~ FM-8)
# 인증 필요 엔드포인트: /api/files/transfer + /api/files/list side=s1
# → /api/test/session 으로 owner 세션 발급 후 cookie jar 로 호출.
set -euo pipefail
source "$(dirname "$0")/test-helpers.sh"
echo "═══ File Manager 테스트 ═══"

JAR=$(mktemp -t fm-test.XXXXXX); trap 'rm -f "$JAR"' EXIT
EMAIL="fm-test-$(date +%s)@example.com"
curl -sf -b "$JAR" -c "$JAR" -X POST "$API/api/test/session" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"role\":\"owner\",\"access_level\":\"allow\"}" > /dev/null

# FM-1: S2 목록
section "FM-1: S2 디렉토리 목록"
S2=$(curl -sf -b "$JAR" "$API/api/files/list?side=s2&path=" || echo "{}")
echo "$S2" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'files' in d" 2>/dev/null && pass "S2 목록 조회" || fail "S2 목록 실패"

# FM-2: S1 목록
section "FM-2: S1 디렉토리 목록"
S1=$(curl -sf -b "$JAR" "$API/api/files/list?side=s1&path=" || echo "{}")
echo "$S1" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'files' in d" 2>/dev/null && pass "S1 목록 조회" || fail "S1 목록 실패"

if ! docker ps --format '{{.Names}}' | grep -q "$SANDBOX"; then
  warn "sandbox 없음 — 전송 테스트 생략"
  summary; exit $?
fi

# FM-4: S2→S1 안전 파일 (guardrail pass)
section "FM-4: S2→S1 안전 파일 전송"
# Determine S2 mount root inside proxy container (same as boan-sandbox mount)
S2ROOT=$(docker exec boanclaw-boan-sandbox-1 sh -c 'echo ${BOAN_MOUNT_ROOT:-/home/boan/Desktop/boanclaw}' 2>/dev/null | tr -d '\r\n')
docker exec boanclaw-boan-sandbox-1 sh -c "mkdir -p '$S2ROOT' && echo 'hello safe' > '$S2ROOT/test-safe.txt'" 2>/dev/null
RESP=$(curl -sf -b "$JAR" -X POST "$API/api/files/transfer" -H "Content-Type: application/json" \
  -d '{"file_name":"test-safe.txt","src_side":"s2","src_path":"","dst_path":""}' || echo '{"ok":false}')
OK=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ok',False))" 2>/dev/null)
[ "$OK" = "True" ] && pass "안전 파일 전송 성공" || fail "전송 실패: $RESP"

# FM-5: S2→S1 위험 파일 (credential pattern → G1 block)
section "FM-5: S2→S1 위험 파일 차단"
docker exec boanclaw-boan-sandbox-1 sh -c "echo 'my github token: ghp_AAAAAAAAAAAAAAAAAAAABCDEFGHIJKLMNOP' > '$S2ROOT/test-danger.txt'" 2>/dev/null
RESP=$(curl -sf -b "$JAR" -X POST "$API/api/files/transfer" -H "Content-Type: application/json" \
  -d '{"file_name":"test-danger.txt","src_side":"s2","src_path":"","dst_path":""}' || echo '{"ok":false}')
OK=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ok',False))" 2>/dev/null)
[ "$OK" = "False" ] && pass "위험 파일 차단됨" || fail "위험 파일 통과됨"

# FM-7: 폴더 전송 차단
section "FM-7: 폴더 전송 차단"
docker exec boanclaw-boan-sandbox-1 sh -c "mkdir -p '$S2ROOT/test-dir'" 2>/dev/null
RESP=$(curl -sf -b "$JAR" -X POST "$API/api/files/transfer" -H "Content-Type: application/json" \
  -d '{"file_name":"test-dir","src_side":"s2","src_path":"","dst_path":""}' || echo '{"ok":false}')
OK=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ok',False))" 2>/dev/null)
[ "$OK" = "False" ] && pass "폴더 전송 차단" || fail "폴더 전송 허용됨"

# FM-8: 경로 탈출 방지
section "FM-8: 경로 탈출 방지"
CODE=$(curl -so /dev/null -w '%{http_code}' -b "$JAR" -X POST "$API/api/files/transfer" -H "Content-Type: application/json" \
  -d '{"file_name":"passwd","src_side":"s2","src_path":"../../../etc","dst_path":""}')
[ "$CODE" = "403" ] && pass "경로 탈출 차단 (403)" || fail "경로 탈출 (HTTP $CODE)"

# 정리
docker exec boanclaw-boan-sandbox-1 sh -c "rm -f '$S2ROOT/test-safe.txt' '$S2ROOT/test-danger.txt'; rmdir '$S2ROOT/test-dir' 2>/dev/null" 2>/dev/null || true
curl -sf -X POST "$API/api/test/cleanup-user" -H "Content-Type: application/json" -d "{\"email\":\"$EMAIL\"}" > /dev/null 2>&1 || true

summary
