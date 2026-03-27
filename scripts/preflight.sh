#!/usr/bin/env bash
set -euo pipefail

FAIL=0
SECURITY_WARNINGS=0
RUN_SECURITY=0

for arg in "$@"; do
  if [ "$arg" = "--security" ]; then
    RUN_SECURITY=1
  fi
done

if [ "${BOAN_SECURITY_PREFLIGHT:-}" = "1" ]; then
  RUN_SECURITY=1
fi

check() {
  local label=$1; shift
  if "$@" &>/dev/null; then
    echo "  [ok] $label"
  else
    echo "  [FAIL] $label"
    FAIL=1
  fi
}

check_security() {
  DESC="$1"; shift
  if "$@" 2>/dev/null; then
    printf "  [SECURITY OK]  %s\n" "$DESC"
  else
    printf "  [SECURITY WARN] %s\n" "$DESC"
    SECURITY_WARNINGS=$((SECURITY_WARNINGS + 1))
  fi
}

version_check() {
  local cmd=$1 min=$2
  if ! command -v "$cmd" &>/dev/null; then
    echo "  [FAIL] $cmd not installed"
    FAIL=1
    return
  fi
  local ver
  ver=$("$cmd" --version 2>&1 | grep -oP '\d+\.\d+' | head -1)
  echo "  [ok] $cmd $ver (minimum: $min)"
}

echo "BoanClaw Preflight Check"
echo ""

echo "Runtime:"
check "docker available"   command -v docker
check "docker running"     docker info
version_check "go" "1.22"
version_check "node" "20"

echo ""
echo "Ports:"
REQUIRED_PORTS=(18080 18081 18090 18092 18093 18094 18095 18096 18099)
for port in "${REQUIRED_PORTS[@]}"; do
  if command -v ss &>/dev/null; then
    check "port $port free" bash -c "! ss -tlnp 2>/dev/null | grep -q ':${port} '"
  elif command -v lsof &>/dev/null; then
    check "port $port free" bash -c "! lsof -iTCP:${port} -sTCP:LISTEN &>/dev/null"
  else
    echo "  [skip] port $port (no ss/lsof)"
  fi
done

echo ""
echo "Environment:"
if [ -n "${BOAN_ORG_ID:-}" ]; then
  echo "  [ok] BOAN_ORG_ID=$BOAN_ORG_ID"
else
  echo "  [warn] BOAN_ORG_ID not set (will default to dev-org)"
fi

echo ""
echo "Docker Compose:"
if docker compose version &>/dev/null 2>&1; then
  echo "  [ok] docker compose plugin"
elif command -v docker-compose &>/dev/null; then
  echo "  [ok] docker-compose standalone"
else
  echo "  [FAIL] docker compose not available"
  FAIL=1
fi

if command -v wsl.exe &>/dev/null; then
  echo ""
  echo "WSL2:"
  check "docker socket" bash -c "[ -S /var/run/docker.sock ]"
fi

if [ "$RUN_SECURITY" = "1" ]; then
  echo ""
  echo "=== Security Preflight ==="

  check_security "cosign available" command -v cosign

  check_security "boan CA key exists" test -f "${BOAN_CA_KEY:-/etc/boan-ca/ca.key}"

  check_security "boan-proxy health" curl -sf "${BOAN_PROXY_URL:-http://localhost:18080}/healthz" > /dev/null 2>&1

  check_security "policy-server health" curl -sf "${BOAN_POLICY_URL:-http://localhost:8081}/healthz" > /dev/null 2>&1

  check_security "onecli health" curl -sf "${BOAN_ONECLI_URL:-http://localhost:8083}/healthz" > /dev/null 2>&1

  check_security "network policy pubkey configured" test -n "${BOAN_NETWORK_POLICY_PUBKEY:-}"

  check_security "no ANTHROPIC_API_KEY in env (use OneCLI)" [ -z "${ANTHROPIC_API_KEY:-}" ]
  check_security "no OPENAI_API_KEY in env (use OneCLI)" [ -z "${OPENAI_API_KEY:-}" ]

  if command -v kubectl > /dev/null 2>&1; then
    check_security "k8s NetworkPolicy exists" kubectl get networkpolicy -n boanclaw default-deny-all > /dev/null 2>&1
  fi

  echo ""
  if [ "$SECURITY_WARNINGS" -gt 0 ]; then
    echo "security preflight: $SECURITY_WARNINGS warning(s) — review above items"
  else
    echo "all security checks passed"
  fi
fi

echo ""
if [ $FAIL -ne 0 ]; then
  echo "preflight FAILED — fix above issues before proceeding"
  exit 1
fi
echo "all preflight checks passed"
