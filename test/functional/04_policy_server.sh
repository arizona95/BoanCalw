#!/usr/bin/env bash
ADMIN_URL="${BOAN_ADMIN_URL:-http://localhost:18081}"
POLICY_URL="${BOAN_POLICY_URL:-http://localhost:8081}"
ORG="${BOAN_ORG_ID:-dev-org}"

RESP=$(curl -sf "${ADMIN_URL}/api/policy/v1/policy")
echo "$RESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'org_id' in d or 'version' in d, f'GET /api/policy/v1/policy: unexpected response: {d}'
"

curl -sf -X POST "${ADMIN_URL}/api/policy/v1/policy" \
  -H "Content-Type: application/json" \
  -d "{\"org_id\":\"${ORG}\",\"network_whitelist\":[{\"host\":\"api.anthropic.com\",\"ports\":[443]}],\"allow_models\":[\"claude-3-5-sonnet\"]}" \
  -o /dev/null

RESP2=$(curl -sf "${ADMIN_URL}/api/policy/v1/policy")
echo "$RESP2" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'version' in d, f'POST then GET: version missing: {d}'
assert d.get('version', 0) >= 1, f'version should be >= 1: {d}'
"

NET_RESP=$(curl -sf "${POLICY_URL}/org/${ORG}/network-policy.json")
echo "$NET_RESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'policy' in d and 'signature' in d, f'network-policy: missing fields: {d}'
"
