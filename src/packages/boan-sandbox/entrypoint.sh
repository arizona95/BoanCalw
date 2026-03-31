#!/bin/sh
set -e

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
boan-onecli &
ONECLI_PID=$!

for i in $(seq 1 15); do
    curl -sf http://localhost:8083/healthz > /dev/null 2>&1 && break
    sleep 1
done
curl -sf http://localhost:8083/healthz > /dev/null 2>&1 || echo "[boan-sandbox] WARNING: onecli not ready, continuing anyway"

echo "[boan-sandbox] running openclaw doctor --fix"
openclaw doctor --fix 2>/dev/null || echo "[boan-sandbox] doctor returned non-zero (continuing)"

echo "[boan-sandbox] installing boan-agent plugin from /opt/boanclaw"
openclaw plugin install /opt/boanclaw 2>/dev/null || echo "[boan-sandbox] plugin install skipped (may already be installed)"

echo "[boan-sandbox] starting openclaw gateway on port 18789"
exec openclaw gateway --port 18789
