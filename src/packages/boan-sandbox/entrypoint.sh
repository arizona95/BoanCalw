#!/bin/sh
set -e

as_boan() {
    gosu boan "$@"
}

# Block environment variables that can exfiltrate TLS keys, hijack dynamic linker, or override Node.js behavior
DANGEROUS_ENV_VARS="
SSLKEYLOGFILE
NODE_OPTIONS
NODE_PATH
NODE_EXTRA_CA_CERTS
LD_PRELOAD
LD_LIBRARY_PATH
LD_AUDIT
LD_DEBUG
DYLD_INSERT_LIBRARIES
DYLD_LIBRARY_PATH
PYTHONPATH
PYTHONSTARTUP
RUBYOPT
JAVA_TOOL_OPTIONS
_JAVA_OPTIONS
JDK_JAVA_OPTIONS
BASH_ENV
ENV
CDPATH
"

for VAR in $DANGEROUS_ENV_VARS; do
    if [ -n "$(eval echo \${$VAR:-})" ]; then
        echo "[boan-sandbox] SECURITY: unsetting dangerous env var: $VAR"
        unset "$VAR" || true
    fi
done

/mount-check.sh

mkdir -p /workspace/boanclaw
mkdir -p /tmp/boan/users /tmp/boan/registry /tmp/boan/credentials
mkdir -p /data/users /data/registry /data/credentials
chown -R boan:boan /workspace /tmp/boan /data /home/boan /etc/boan-cred 2>/dev/null || true

echo "[boan-sandbox] starting credential-filter on :8082"
BOAN_LISTEN=:8082 BOAN_KMS_KEY="${BOAN_KMS_KEY:-/etc/boan-cred/aes.key}" BOAN_DATA_DIR="${BOAN_CREDENTIAL_DATA_DIR:-/data/credentials}" as_boan boan-credential-filter &
CRED_PID=$!

echo "[boan-sandbox] starting llm-registry on :8086"
BOAN_LISTEN=:8086 BOAN_DATA_DIR="${BOAN_DATA_DIR:-/data/registry}" as_boan boan-llm-registry &
REG_PID=$!

echo "[boan-sandbox] starting whitelist-proxy on :8085"
BOAN_LISTEN=:8085 BOAN_LLM_URL="${BOAN_WHITELIST_LLM_URL:-http://localhost:18081/api/openclaw}" as_boan boan-whitelist-proxy &
WL_PID=$!

echo "[boan-sandbox] starting boan-proxy inside sandbox package"
BOAN_LISTEN="${BOAN_LISTEN:-:18080}" BOAN_ADMIN_LISTEN="${BOAN_ADMIN_LISTEN:-:18081}" as_boan boan-proxy &
PROXY_PID=$!

for i in $(seq 1 20); do
    curl -sf http://localhost:18081/healthz > /dev/null 2>&1 && break
    sleep 1
done
curl -sf http://localhost:18081/healthz > /dev/null 2>&1 || echo "[boan-sandbox] WARNING: boan-proxy admin not ready, continuing anyway"

for ENVFILE in /workspace/.env /workspace/.env.local /workspace/.env.production /workspace/.env.secret; do
    if [ -f "$ENVFILE" ]; then
        echo "[boan-sandbox] SECURITY: shadowing $ENVFILE with /dev/null bind"
        mount --bind /dev/null "$ENVFILE" 2>/dev/null || {
            echo "[boan-sandbox] WARNING: could not shadow $ENVFILE (no CAP_SYS_ADMIN), truncating instead"
            cp /dev/null "$ENVFILE" || true
        }
    fi
done

echo "[boan-sandbox] starting boan-onecli credential proxy on :8083"
as_boan boan-onecli &
ONECLI_PID=$!

for i in $(seq 1 15); do
    curl -sf http://localhost:8083/healthz > /dev/null 2>&1 && break
    sleep 1
done
curl -sf http://localhost:8083/healthz > /dev/null 2>&1 || echo "[boan-sandbox] WARNING: onecli not ready, continuing anyway"

echo "[boan-sandbox] preparing openclaw state directories"
mkdir -p /home/boan/.openclaw/agents/main/sessions
chown -R boan:boan /home/boan/.openclaw 2>/dev/null || true
chmod 700 /home/boan/.openclaw || true

echo "[boan-sandbox] configuring OpenClaw model from org-selected provider"
OPENCLAW_CFG_JSON="$(curl -sf http://localhost:18081/api/openclaw/config || true)"
if [ -z "$OPENCLAW_CFG_JSON" ]; then
  OPENCLAW_CFG_JSON='{"base_url":"http://localhost:18081/api/openclaw/v1","model_id":"security","model_name":"security","provider":"boan"}'
fi
OPENCLAW_CFG_JSON="$OPENCLAW_CFG_JSON" as_boan node <<'JS'
const fs = require("fs");
const path = "/home/boan/.openclaw/openclaw.json";
let cfg = {};
try {
  cfg = JSON.parse(fs.readFileSync(path, "utf8"));
} catch (_) {
  cfg = {};
}
const data = JSON.parse(process.env.OPENCLAW_CFG_JSON || "{}");
const provider = data.provider || "boan";
const modelId = data.model_id || "security";
const modelName = data.model_name || modelId;
const baseUrl = data.base_url || "http://boan-proxy:18081/api/openclaw/v1";
cfg.models = cfg.models || {};
cfg.models.mode = "merge";
cfg.models.providers = cfg.models.providers || {};
cfg.models.providers[provider] = {
  baseUrl,
  apiKey: "boan-managed",
  api: "openai-completions",
  models: [{
    id: modelId,
    name: modelName,
    reasoning: false,
    input: ["text"],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: 131072,
    maxTokens: 4096
  }]
};
cfg.agents = cfg.agents || {};
cfg.agents.defaults = cfg.agents.defaults || {};
cfg.agents.defaults.model = { primary: `${provider}/${modelId}` };
cfg.agents.defaults.models = { [`${provider}/${modelId}`]: {} };
fs.writeFileSync(path, JSON.stringify(cfg, null, 2), { mode: 0o600 });
JS

echo "[boan-sandbox] configuring openclaw gateway mode"
as_boan openclaw config set gateway.mode local 2>/dev/null || echo "[boan-sandbox] gateway.mode set skipped"
as_boan openclaw config set gateway.auth.mode token 2>/dev/null || echo "[boan-sandbox] gateway.auth.mode set skipped"
as_boan openclaw config set gateway.auth.token "${BOAN_OPENCLAW_GATEWAY_TOKEN:-boan-openclaw-local}" 2>/dev/null || echo "[boan-sandbox] gateway.auth.token set skipped"
as_boan openclaw config set gateway.bind lan 2>/dev/null || echo "[boan-sandbox] gateway.bind set skipped"
as_boan openclaw config set gateway.controlUi.basePath /openclaw 2>/dev/null || echo "[boan-sandbox] gateway.controlUi.basePath set skipped"
as_boan openclaw config set gateway.controlUi.allowedOrigins '["http://localhost:19080"]' --strict-json 2>/dev/null || echo "[boan-sandbox] gateway.controlUi.allowedOrigins set skipped"
as_boan openclaw config set gateway.controlUi.allowInsecureAuth true 2>/dev/null || echo "[boan-sandbox] gateway.controlUi.allowInsecureAuth set skipped"
as_boan openclaw config set gateway.controlUi.dangerouslyDisableDeviceAuth true 2>/dev/null || echo "[boan-sandbox] gateway.controlUi.dangerouslyDisableDeviceAuth set skipped"

echo "[boan-sandbox] installing boan-agent plugin from /opt/boanclaw"
as_boan openclaw plugins install --dangerously-force-unsafe-install /opt/boanclaw 2>&1 || echo "[boan-sandbox] plugin install failed, continuing"

echo "[boan-sandbox] starting openclaw gateway on port 18789"
exec gosu boan openclaw gateway run --port 18789 --bind lan --token "${BOAN_OPENCLAW_GATEWAY_TOKEN:-boan-openclaw-local}"
