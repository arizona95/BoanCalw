#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/src/packages/boan-sandbox"

[ -f "${SCRIPT_DIR}/entrypoint.sh" ] || exit 1
grep -q "SSLKEYLOGFILE" "${SCRIPT_DIR}/entrypoint.sh"
grep -q "LD_PRELOAD" "${SCRIPT_DIR}/entrypoint.sh"
grep -q "NODE_OPTIONS" "${SCRIPT_DIR}/entrypoint.sh"
grep -q "DYLD_INSERT_LIBRARIES" "${SCRIPT_DIR}/entrypoint.sh"
