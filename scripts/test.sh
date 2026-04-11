#!/usr/bin/env bash
# BoanClaw 전체 테스트 실행
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ERRORS=0

echo "╔═══════════════════════════════════════════════╗"
echo "║       BoanClaw 전체 테스트 실행                ║"
echo "╚═══════════════════════════════════════════════╝"

# ── Go 단위 테스트 ──
echo ""
echo "▶ Go 단위 테스트"
for pkg in boan-proxy boan-policy-server; do
  if [ -d "$ROOT/src/packages/$pkg" ] && [ -f "$ROOT/src/packages/$pkg/go.mod" ]; then
    echo "  testing $pkg..."
    (cd "$ROOT/src/packages/$pkg" && go test ./... -count=1 -timeout=60s) || { echo "  FAIL $pkg"; ERRORS=$((ERRORS+1)); }
  fi
done

# ── 통합 테스트 ──
echo ""
echo "▶ 통합 테스트"
for script in \
  "$ROOT/scripts/test-services.sh" \
  "$ROOT/scripts/test-users.sh" \
  "$ROOT/scripts/test-network.sh" \
  "$ROOT/scripts/test-files.sh" \
  "$ROOT/scripts/test-credential-vault.sh"; do
  if [ -f "$script" ]; then
    echo ""
    bash "$script" || ERRORS=$((ERRORS+1))
  fi
done

# ── 결과 ──
echo ""
echo "╔═══════════════════════════════════════════════╗"
if [ $ERRORS -gt 0 ]; then
  echo "║  전체 결과: $ERRORS개 그룹 실패                    ║"
else
  echo "║  전체 결과: 모두 통과                          ║"
fi
echo "╚═══════════════════════════════════════════════╝"
exit $ERRORS
