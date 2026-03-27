#!/usr/bin/env bash
POLICY_URL="${BOAN_POLICY_URL:-http://localhost:8081}"
ORG="dev-org"

RESP=$(curl -sf "${POLICY_URL}/org/${ORG}/policy.json")
echo "$RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'version' in d or 'endpoints' in d or 'policy' in d"

NET_RESP=$(curl -sf "${POLICY_URL}/org/${ORG}/network-policy.json")
echo "$NET_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'policy' in d or 'endpoints' in d"
