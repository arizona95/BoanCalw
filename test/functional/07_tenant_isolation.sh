#!/usr/bin/env bash
ADMIN_URL="${BOAN_ADMIN_URL:-http://localhost:18081}"

login_as() {
  local org="$1" role="$2"
  curl -sf -c /tmp/boan-cookie-"$org" -X POST "${ADMIN_URL}/api/auth/dev-login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"test@test.com\",\"org_id\":\"${org}\",\"role\":\"${role}\"}" > /dev/null
}

get_policy() {
  local org="$1"
  curl -sf -b /tmp/boan-cookie-"$org" "${ADMIN_URL}/api/policy/v1/policy"
}

save_policy() {
  local org="$1" model="$2"
  curl -sf -b /tmp/boan-cookie-"$org" -X POST "${ADMIN_URL}/api/policy/v1/policy" \
    -H "Content-Type: application/json" \
    -d "{\"allow_models\":[\"${model}\"],\"network_whitelist\":[]}" > /dev/null
}

login_as "org-alpha" "primary_owner"
login_as "org-beta" "primary_owner"

save_policy "org-alpha" "claude-alpha"
save_policy "org-beta" "gpt-beta"

sleep 1

ALPHA_RESP=$(get_policy "org-alpha")
BETA_RESP=$(get_policy "org-beta")

echo "$ALPHA_RESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
models = d.get('allow_models', [])
assert 'claude-alpha' in models, f'org-alpha should have claude-alpha, got: {models}'
assert 'gpt-beta' not in models, f'org-alpha should NOT have gpt-beta, got: {models}'
"

echo "$BETA_RESP" | python3 -c "
import sys, json
d = json.load(sys.stdin)
models = d.get('allow_models', [])
assert 'gpt-beta' in models, f'org-beta should have gpt-beta, got: {models}'
assert 'claude-alpha' not in models, f'org-beta should NOT have claude-alpha, got: {models}'
"

rm -f /tmp/boan-cookie-org-alpha /tmp/boan-cookie-org-beta
