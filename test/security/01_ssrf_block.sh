#!/usr/bin/env bash
PROXY_URL="${BOAN_PROXY_URL:-http://localhost:18080}"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  --proxy "${PROXY_URL}" \
  "http://169.254.169.254/latest/meta-data/" \
  --max-time 5 2>/dev/null || echo "000")

[ "$STATUS" -ne 200 ]
