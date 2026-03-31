#!/usr/bin/env bash
CRED_URL="${BOAN_CRED_URL:-http://localhost:8082}"
ORG="test-org"
ROLE="test-role"

curl -sf -X POST "${CRED_URL}/credential/${ORG}" \
  -H "Content-Type: application/json" \
  -d "{\"role\":\"${ROLE}\",\"key\":\"sk-test-1234\",\"ttl_hours\":24}"

RESP=$(curl -sf "${CRED_URL}/credential/${ORG}/${ROLE}")
echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d.get('status') == 'ok', f'expected ok, got {d}'"

curl -sf -X DELETE "${CRED_URL}/credential/${ORG}/${ROLE}"
