#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/src/packages"
ERRORS=0

if command -v go &>/dev/null; then
  echo "▶ Go unit tests"
  for pkg in boan-proxy boan-policy-server boan-whitelist-proxy boan-llm-registry; do
    if [ -d "$SRC/$pkg" ] && [ -f "$SRC/$pkg/go.mod" ]; then
      echo "  testing $pkg..."
      (cd "$SRC/$pkg" && go test ./... -count=1 -timeout=60s) || { echo "  FAIL $pkg"; ERRORS=$((ERRORS+1)); }
    else
      echo "  skip $pkg"
    fi
  done
else
  echo "  go not found, skipping Go tests"
fi

if command -v node &>/dev/null; then
  echo "▶ TypeScript unit tests"
  for pkg in boan-agent boan-admin-console; do
    if [ -f "$SRC/$pkg/package.json" ]; then
      if [ ! -d "$SRC/$pkg/node_modules" ]; then
        echo "  installing deps for $pkg..."
        (cd "$SRC/$pkg" && npm ci --prefer-offline 2>/dev/null) || true
      fi
      echo "  testing $pkg..."
      (cd "$SRC/$pkg" && npm test -- --run 2>/dev/null) || { echo "  FAIL $pkg"; ERRORS=$((ERRORS+1)); }
    else
      echo "  skip $pkg"
    fi
  done
else
  echo "  node not found, skipping TS tests"
fi

# ── 통합 테스트 (실행 중인 서비스 대상) ──
echo "▶ Integration tests"
for script in "$ROOT/scripts/test-access-level-api.sh" "$ROOT/scripts/test-network-policy.sh" "$ROOT/scripts/test-computer-use.sh"; do
  if [ -x "$script" ]; then
    echo "  running $(basename "$script")..."
    if bash "$script"; then
      echo "  PASS $(basename "$script")"
    else
      echo "  FAIL $(basename "$script")"
      ERRORS=$((ERRORS+1))
    fi
  fi
done

if [ $ERRORS -gt 0 ]; then
  echo "tests completed with $ERRORS failure(s)"
  exit 1
fi
echo "tests done"
