#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Starting BoanClaw test suite"
echo "Stack URL: ${BOAN_PROXY_URL:-http://localhost:18081}"
echo ""

FAIL=0
bash "$DIR/functional/run.sh" || FAIL=1
echo ""
bash "$DIR/security/run.sh" || FAIL=1

echo ""
if [ $FAIL -eq 0 ]; then
  echo "All tests passed"
else
  echo "Some tests failed"
  exit 1
fi
