#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/dowoo/desktop/dowoo/SDS-RED/SDSclawBLUE/BoanClaw"
POLICY_DIR="$ROOT/src/packages/boan-policy-server"
PROXY_DIR="$ROOT/src/packages/boan-proxy"

TMP_DIR="$(mktemp -d)"
mkdir -p "$TMP_DIR/ca"
POLICY_LOG="$TMP_DIR/policy.log"
PROXY_LOG="$TMP_DIR/proxy.log"
POLICY_PID=""
PROXY_PID=""

cleanup() {
  if [ -n "$PROXY_PID" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  if [ -n "$POLICY_PID" ] && kill -0 "$POLICY_PID" 2>/dev/null; then
    kill "$POLICY_PID" 2>/dev/null || true
    wait "$POLICY_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

wait_for() {
  local url="$1"
  for _ in $(seq 1 100); do
    if curl -sf "$url" >/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

MOCK_EMAIL="mock-user@sds.com"
MOCK_PASSWORD="Password123!"
ORG_ID="sds-corp"
COOKIE_JAR="$TMP_DIR/cookies.txt"
POLICY_PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
PROXY_PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
ADMIN_PORT="$(python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"

(
  cd "$POLICY_DIR"
  BOAN_LISTEN=":$POLICY_PORT" \
  BOAN_DATA_DIR="$TMP_DIR/policy-data" \
  BOAN_KEY_DIR="$TMP_DIR/policy-keys" \
  go run . >"$POLICY_LOG" 2>&1
) &
POLICY_PID=$!

wait_for "http://127.0.0.1:$POLICY_PORT/healthz"

(
  cd "$PROXY_DIR"
  BOAN_LISTEN=":$PROXY_PORT" \
  BOAN_ADMIN_LISTEN=":$ADMIN_PORT" \
  BOAN_ORG_ID="$ORG_ID" \
  BOAN_POLICY_URL="http://127.0.0.1:$POLICY_PORT" \
  BOAN_USER_DATA_DIR="$TMP_DIR/proxy-data" \
  BOAN_CA_CERT="$TMP_DIR/ca/ca.crt" \
  BOAN_CA_KEY="$TMP_DIR/ca/ca.key" \
  BOAN_ADMIN_PASSWORD="not-used-here" \
  go run ./cmd/proxy >"$PROXY_LOG" 2>&1
) &
PROXY_PID=$!

wait_for "http://127.0.0.1:$ADMIN_PORT/healthz"

REGISTER_RESP="$(curl -sf -X POST "http://127.0.0.1:$ADMIN_PORT/api/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$MOCK_EMAIL\",\"password\":\"$MOCK_PASSWORD\",\"org_id\":\"$ORG_ID\"}")"
echo "$REGISTER_RESP" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["status"] == "ok", d
assert d["org_id"] == "sds-corp", d
'

LOGIN_RESP="$(curl -sf -c "$COOKIE_JAR" -X POST "http://127.0.0.1:$ADMIN_PORT/api/auth/dev-login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$MOCK_EMAIL\",\"password\":\"$MOCK_PASSWORD\"}")"
echo "$LOGIN_RESP" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["status"] == "ok", d
assert d["org_id"] == "sds-corp", d
'

ME_RESP="$(curl -sf -b "$COOKIE_JAR" "http://127.0.0.1:$ADMIN_PORT/api/auth/me")"
echo "$ME_RESP" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["authenticated"] is True, d
assert d["email"] == "mock-user@sds.com", d
'

USERS_RESP="$(curl -sf "http://127.0.0.1:$POLICY_PORT/org/$ORG_ID/v1/users")"
echo "$USERS_RESP" | python3 -c '
import json, sys
users = json.load(sys.stdin)
assert any(u["email"] == "mock-user@sds.com" for u in users), users
'

echo "mock login flow ok"
