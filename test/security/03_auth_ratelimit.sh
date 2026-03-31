#!/usr/bin/env bash
PROXY_URL="${BOAN_PROXY_URL:-http://localhost:18080}"

for i in $(seq 1 15); do
  curl -s -o /dev/null -X POST "${PROXY_URL}/api/llm-use" \
    -H "X-Boan-Role: wrong-role-$(date +%s%N)" \
    -H "X-Boan-Tool: exec_cmd" \
    -H "Content-Type: application/json" \
    -d '{}' || true
done

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${PROXY_URL}/api/llm-use" \
  -H "X-Boan-Role: wrong-role-final" \
  -H "X-Boan-Tool: exec_cmd" \
  -H "Content-Type: application/json" \
  -d '{}')
[ "$STATUS" -eq 429 ]
