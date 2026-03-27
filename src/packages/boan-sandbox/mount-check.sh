#!/bin/sh
# Validates that no sensitive host paths are mounted in the container.
# Exits non-zero if a dangerous mount is detected.
set -e

BLOCKED_SOURCES="
/etc/passwd
/etc/shadow
/root
/home
/var/run/docker.sock
/var/run/dockershim.sock
/run/docker.sock
/.aws
/.ssh
/.gnupg
/.kube
"

while IFS= read -r line; do
    SRC=$(echo "$line" | awk '{print $1}')
    for BLOCKED in $BLOCKED_SOURCES; do
        case "$SRC" in
            "$BLOCKED"*) 
                echo "[boan-sandbox] FATAL: blocked mount source detected: $SRC"
                exit 1
                ;;
        esac
    done
done < /proc/mounts

echo "[boan-sandbox] mount check passed"
