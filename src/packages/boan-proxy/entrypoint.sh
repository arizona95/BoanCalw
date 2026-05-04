#!/bin/sh
# Bind-mounted /data/users can come up with host-side ownership (e.g. 1000:1000),
# which the boan UID inside the container can't read — killchain.NewStore then
# fails silently and the kill-chain endpoints are skipped (404 on webhook).
# Always reassert ownership at startup; idempotent.
set -eu
chown -R boan:boan /data/users 2>/dev/null || true
chmod 775 /data/users 2>/dev/null || true
exec su-exec boan:boan boan-proxy "$@"
