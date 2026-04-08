#!/usr/bin/env bash
# 파일 전송 API 테스트 — S2↔S1 가드레일 검사 검증
set -euo pipefail

API="http://localhost:19080"
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'
ERRORS=0
pass() { echo -e "  ${GREEN}✓${NC} $1"; }
fail() { echo -e "  ${RED}✗${NC} $1"; ERRORS=$((ERRORS+1)); }

SANDBOX="boanclaw-boan-sandbox-1"

echo "═══════════════════════════════════════════════"
echo " File Transfer API 테스트"
echo "═══════════════════════════════════════════════"

# ── 1. S2 디렉토리 목록 ──
echo "▶ [1/5] S2 디렉토리 목록 조회"
S2_RESP=$(curl -sf "$API/api/files/list?side=s2&path=" 2>/dev/null || echo "{}")
if echo "$S2_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'files' in d" 2>/dev/null; then
  FILE_COUNT=$(echo "$S2_RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['files']))" 2>/dev/null)
  pass "S2 목록 조회 성공 (파일 ${FILE_COUNT}개)"
else
  fail "S2 목록 조회 실패"
fi

# ── 2. S1 디렉토리 목록 ──
echo "▶ [2/5] S1 디렉토리 목록 조회"
S1_RESP=$(curl -sf "$API/api/files/list?side=s1&path=" 2>/dev/null || echo "{}")
if echo "$S1_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'files' in d" 2>/dev/null; then
  pass "S1 목록 조회 성공"
else
  fail "S1 목록 조회 실패"
fi

# ── 3. 테스트 파일 생성 + S2→S1 안전 파일 전송 ──
echo "▶ [3/5] S2→S1 안전 파일 전송 (가드레일 통과 예상)"
# sandbox 안에 테스트 파일 생성
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "$SANDBOX"; then
  docker exec "$SANDBOX" sh -c 'mkdir -p /workspace/boanclaw && echo "hello safe content" > /workspace/boanclaw/test-safe.txt'
  TRANSFER_RESP=$(curl -sf -X POST "$API/api/files/transfer" \
    -H "Content-Type: application/json" \
    -d '{"file_name":"test-safe.txt","src_side":"s2","src_path":"","dst_path":""}' 2>/dev/null || echo '{"ok":false}')
  IS_OK=$(echo "$TRANSFER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ok',False))" 2>/dev/null)
  if [ "$IS_OK" = "True" ]; then
    pass "안전 파일 전송 성공"
  else
    fail "안전 파일 전송 실패: $TRANSFER_RESP"
  fi
else
  fail "sandbox 컨테이너 없음"
fi

# ── 4. S2→S1 위험 파일 전송 (가드레일 차단 예상) ──
echo "▶ [4/5] S2→S1 위험 파일 전송 (가드레일 차단 예상)"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "$SANDBOX"; then
  docker exec "$SANDBOX" sh -c 'echo "password=sk-ant-api03-secret1234567890abcdef export SECRET_KEY=AKIA1234567890" > /workspace/boanclaw/test-danger.txt'
  DANGER_RESP=$(curl -sf -X POST "$API/api/files/transfer" \
    -H "Content-Type: application/json" \
    -d '{"file_name":"test-danger.txt","src_side":"s2","src_path":"","dst_path":""}' 2>/dev/null || echo '{"ok":false}')
  IS_OK=$(echo "$DANGER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ok',False))" 2>/dev/null)
  if [ "$IS_OK" = "False" ]; then
    REASON=$(echo "$DANGER_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('reason',d.get('error','')))" 2>/dev/null)
    pass "위험 파일 전송 차단됨: $REASON"
  else
    fail "위험 파일이 차단되지 않음"
  fi
else
  fail "sandbox 컨테이너 없음"
fi

# ── 5. 디렉토리 전송 차단 ──
echo "▶ [5/5] 디렉토리 전송 시도 (차단 예상)"
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "$SANDBOX"; then
  docker exec "$SANDBOX" sh -c 'mkdir -p /workspace/boanclaw/test-dir'
  DIR_RESP=$(curl -sf -X POST "$API/api/files/transfer" \
    -H "Content-Type: application/json" \
    -d '{"file_name":"test-dir","src_side":"s2","src_path":"","dst_path":""}' 2>/dev/null || echo '{"ok":false}')
  IS_OK=$(echo "$DIR_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('ok',False))" 2>/dev/null)
  if [ "$IS_OK" = "False" ]; then
    pass "디렉토리 전송 차단됨"
  else
    fail "디렉토리 전송이 허용됨"
  fi
  # 정리
  docker exec "$SANDBOX" sh -c 'rm -f /workspace/boanclaw/test-safe.txt /workspace/boanclaw/test-danger.txt; rmdir /workspace/boanclaw/test-dir 2>/dev/null || true'
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
