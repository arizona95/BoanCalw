#!/usr/bin/env bash
SANDBOX_ONECLI_URL="${BOAN_SANDBOX_ONECLI_URL:-}"

if [ -z "$SANDBOX_ONECLI_URL" ]; then
  echo "SKIP: boan-onecli runs inside sandbox (localhost:8083 inside pod); set BOAN_SANDBOX_ONECLI_URL to test externally"
  exit 0
fi

curl -sf "${SANDBOX_ONECLI_URL}/healthz" | grep -q "ok"

STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "${SANDBOX_ONECLI_URL}/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-3","messages":[{"role":"user","content":"hi"}]}')

[ "$STATUS" -ne 500 ]
