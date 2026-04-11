#!/usr/bin/env bash
# 테스트: File Manager (FM-1 ~ FM-8)
set -euo pipefail
source "$(dirname "$0")/test-helpers.sh"
echo "═══ File Manager 테스트 ═══"

# FM-1: S2 목록
section "FM-1: S2 디렉토리 목록"
S2=$(curl -sf "$API/api/files/list?side=s2&path=" || echo "{}")
echo "$S2" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'files' in d" 2>/dev/null && pass "S2 목록 조회" || fail "S2 목록 실패"

# FM-2: S1 목록
section "FM-2: S1 디렉토리 목록"
S1=$(curl -sf "$API/api/files/list?side=s1&path=" || echo "{}")
echo "$S1" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'files' in d" 2>/dev/null && pass "S1 목록 조회" || fail "S1 목록 실패"

if ! docker ps --format '{{.Names}}' | grep -q "$SANDBOX"; then
  warn "sandbox 없음 — 전송 테스트 생략"
  summary; exit $?
fi

# FM-4: S2→S1 안전 파일
section "FM-4: S2→S1 안전 파일 전송"
sandbox_exec sh -c 'mkdir -p /workspace/boanclaw && echo "hello safe" > /workspace/boanclaw/test-safe.txt'
RESP=$(curl -sf -X POST "$API/api/files/transfer" -H "Content-Type: application/json" \
  -d '{"file_name":"test-safe.txt","src_side":"s2","src_path":"","dst_path":""}' || echo '{"ok":false}')
OK=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ok',False))" 2>/dev/null)
[ "$OK" = "True" ] && pass "안전 파일 전송 성공" || fail "전송 실패: $RESP"

# FM-5: S2→S1 위험 파일 (credential)
section "FM-5: S2→S1 위험 파일 차단"
sandbox_exec sh -c 'echo "password=sk-ant-api03-secret1234567890abcdef" > /workspace/boanclaw/test-danger.txt'
RESP=$(curl -sf -X POST "$API/api/files/transfer" -H "Content-Type: application/json" \
  -d '{"file_name":"test-danger.txt","src_side":"s2","src_path":"","dst_path":""}' || echo '{"ok":false}')
OK=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ok',False))" 2>/dev/null)
[ "$OK" = "False" ] && pass "위험 파일 차단됨" || fail "위험 파일 통과됨"

# FM-7: 폴더 전송 차단
section "FM-7: 폴더 전송 차단"
sandbox_exec sh -c 'mkdir -p /workspace/boanclaw/test-dir'
RESP=$(curl -sf -X POST "$API/api/files/transfer" -H "Content-Type: application/json" \
  -d '{"file_name":"test-dir","src_side":"s2","src_path":"","dst_path":""}' || echo '{"ok":false}')
OK=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ok',False))" 2>/dev/null)
[ "$OK" = "False" ] && pass "폴더 전송 차단" || fail "폴더 전송 허용됨"

# FM-8: 경로 탈출 방지
section "FM-8: 경로 탈출 방지"
CODE=$(curl -so /dev/null -w '%{http_code}' -X POST "$API/api/files/transfer" -H "Content-Type: application/json" \
  -d '{"file_name":"passwd","src_side":"s2","src_path":"../../../etc","dst_path":""}')
[ "$CODE" = "403" ] && pass "경로 탈출 차단 (403)" || fail "경로 탈출 (HTTP $CODE)"

# 정리
sandbox_exec sh -c 'rm -f /workspace/boanclaw/test-safe.txt /workspace/boanclaw/test-danger.txt; rmdir /workspace/boanclaw/test-dir 2>/dev/null' || true

summary
