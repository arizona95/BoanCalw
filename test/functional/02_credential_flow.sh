#!/usr/bin/env bash
CRED_URL="${BOAN_CRED_URL:-http://localhost:8082}"
ORG="test-org"
CRED_NAME="test-api-key"

curl -sf -X POST "${CRED_URL}/credential/${ORG}" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"${CRED_NAME}\",\"value\":\"sk-test-1234\",\"header\":\"x-api-key\",\"expires_at\":\"2099-01-01T00:00:00Z\"}"

RESP=$(curl -sf "${CRED_URL}/credential/${ORG}/${CRED_NAME}")
echo "$RESP" | grep -q "test-api-key"

curl -sf -X DELETE "${CRED_URL}/credential/${ORG}/${CRED_NAME}"
