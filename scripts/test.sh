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

if [ $ERRORS -gt 0 ]; then
  echo "tests completed with $ERRORS failure(s)"
  exit 1
fi
echo "tests done"
