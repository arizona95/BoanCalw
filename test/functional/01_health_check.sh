#!/usr/bin/env bash
PROXY_URL="${BOAN_PROXY_URL:-http://localhost:18081}"
POLICY_URL="${BOAN_POLICY_URL:-http://localhost:8081}"
CRED_URL="${BOAN_CRED_URL:-http://localhost:8082}"

curl -sf "${PROXY_URL}/healthz" | grep -q "ok"
curl -sf "${POLICY_URL}/healthz" | grep -q "ok"
curl -sf "${CRED_URL}/healthz" | grep -q "ok"
