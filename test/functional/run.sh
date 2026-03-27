#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0; FAIL=0

run_test() {
    local name="$1"; local script="$2"
    printf "  %-50s" "$name"
    if bash "$script" > /tmp/boan-test-out 2>&1; then
        echo "[PASS]"; PASS=$((PASS+1))
    else
        echo "[FAIL]"; FAIL=$((FAIL+1))
        cat /tmp/boan-test-out | head -5 | sed 's/^/    /'
    fi
}

echo "=== BoanClaw Functional Tests ==="
run_test "health: boan-proxy"         "$DIR/01_health_check.sh"
run_test "health: credential-filter"  "$DIR/02_credential_flow.sh"
run_test "health: onecli gateway"     "$DIR/03_onecli_proxy.sh"
run_test "health: policy-server"      "$DIR/04_policy_server.sh"
run_test "rate-limit: 429 on exceed"  "$DIR/05_rate_limit.sh"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] || exit 1
