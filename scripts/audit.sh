#!/usr/bin/env bash
set -euo pipefail

MODE="${1:---json}"
PROXY_ADMIN="http://localhost:18081"

if ! curl -sf "$PROXY_ADMIN/healthz" &>/dev/null; then
  echo "boan-proxy is not reachable at $PROXY_ADMIN"
  echo "start the stack first: ./scripts/dev.sh  or  boanclaw start"
  exit 1
fi

if command -v docker &>/dev/null && docker ps --format '{{.Names}}' | grep -q boan-proxy; then
  docker exec boan-proxy boan-audit "$MODE"
else
  curl -sf "$PROXY_ADMIN/audit?format=${MODE#--}" 2>/dev/null || echo "audit endpoint not available"
fi
