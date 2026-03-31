#!/usr/bin/env bash
ADMIN_URL="${BOAN_ADMIN_URL:-http://localhost:18081}"
ORG="${BOAN_ORG_ID:-dev-org}"

RESP=$(curl -sf "${ADMIN_URL}/api/policy/v1/policy")
echo "$RESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, dict), f'policy GET not a dict: {d}'
"

curl -sf -X POST "${ADMIN_URL}/api/policy/v1/policy" \
  -H "Content-Type: application/json" \
  -d '{"network_whitelist":[],"allow_models":["test-model"]}' \
  -w "\n%{http_code}" -o /tmp/bff_policy_out | grep -qE "^(200|201)$"

CRED_LIST=$(curl -sf "${ADMIN_URL}/api/credential/v1/credentials")
echo "$CRED_LIST" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, list), f'credential list not a list: {d}'
"

REG_LIST=$(curl -sf "${ADMIN_URL}/api/registry/v1/llms")
echo "$REG_LIST" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert isinstance(d, list), f'llm registry list not a list: {d}'
"

curl -sf -c /tmp/bff-test-cookie -X POST "${ADMIN_URL}/api/auth/dev-login" \
  -H "Content-Type: application/json" \
  -d '{"email":"bff-test@test.com","org_id":"bff-test-org","role":"primary_owner"}' > /dev/null

AUTH_RESP=$(curl -sf -b /tmp/bff-test-cookie "${ADMIN_URL}/api/auth/me")
echo "$AUTH_RESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'role' in d and 'can_edit' in d, f'/api/auth/me missing fields: {d}'
assert d.get('authenticated') == True, f'should be authenticated: {d}'
"
rm -f /tmp/bff-test-cookie
