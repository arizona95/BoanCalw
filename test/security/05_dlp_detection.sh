#!/usr/bin/env bash
PROXY_URL="${BOAN_PROXY_URL:-http://localhost:18080}"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${PROXY_URL}/api/llm-use" \
  -H "Content-Type: application/json" \
  -H "X-Boan-Role: developer_or_admin" \
  -d '{"prompt":"Here is my API key: sk-ant-api03-AAABBBCCC123456789","model":"default","sessionId":"test"}')

[ "$STATUS" -ne 500 ]
