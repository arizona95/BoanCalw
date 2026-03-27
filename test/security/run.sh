#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PASS=0; FAIL=0

run_sec() {
    local name="$1"; local script="$2"
    printf "  %-55s" "$name"
    if bash "$script" > /tmp/boan-sec-out 2>&1; then
        echo "[PASS]"; PASS=$((PASS+1))
    else
        echo "[FAIL]"; FAIL=$((FAIL+1))
        cat /tmp/boan-sec-out | head -5 | sed 's/^/    /'
    fi
}

echo "=== BoanClaw Security Tests ==="
run_sec "SSRF: metadata endpoint blocked"         "$DIR/01_ssrf_block.sh"
run_sec "Prompt injection: header warning set"    "$DIR/02_prompt_injection.sh"
run_sec "Auth rate limit: 429 after failures"     "$DIR/03_auth_ratelimit.sh"
run_sec "Env sanitization: test script"           "$DIR/04_env_sanitization.sh"
run_sec "DLP: sensitive content detection"        "$DIR/05_dlp_detection.sh"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] || exit 1
