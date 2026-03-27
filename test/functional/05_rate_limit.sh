#!/usr/bin/env bash
PROXY_URL="${BOAN_PROXY_URL:-http://localhost:18081}"

for i in $(seq 1 12); do
  curl -s -o /dev/null "${PROXY_URL}/api/llm-use" \
    -H "X-Boan-Role: invalid-role-xxxx" \
    -X POST -d '{}' -H "Content-Type: application/json"
done

STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${PROXY_URL}/api/llm-use" \
  -H "X-Boan-Role: invalid-role-xxxx" \
  -X POST -d '{}' -H "Content-Type: application/json")
[ "$STATUS" -eq 429 ]
