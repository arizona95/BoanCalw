#!/usr/bin/env bash
# update-watcher.sh - host-side daemon that polls for update trigger
# Started by install.sh, runs in background, checks every 10s
set -euo pipefail

INSTALL_DIR="${1:-$HOME/boanclaw}"
TRIGGER_FILE="/tmp/boanclaw-update-trigger"
LOG_FILE="/tmp/boanclaw-update.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

log "update-watcher started (install_dir=$INSTALL_DIR, trigger=$TRIGGER_FILE)"

while true; do
  if [ -f "$TRIGGER_FILE" ]; then
    log "update triggered"
    rm -f "$TRIGGER_FILE"

    cd "$INSTALL_DIR"

    # 1. git pull
    if git pull --ff-only >> "$LOG_FILE" 2>&1; then
      log "git pull OK"
    else
      log "git pull failed, trying git pull --rebase"
      git pull --rebase >> "$LOG_FILE" 2>&1 || { log "git pull failed"; continue; }
    fi

    # 2. update version file
    git rev-parse --short HEAD > "$INSTALL_DIR/.boanclaw-version"
    log "version updated to $(cat "$INSTALL_DIR/.boanclaw-version")"

    # 3. rebuild (proxy/sandbox/console)
    log "starting rebuild..."
    if bash "$INSTALL_DIR/scripts/rebuild.sh" >> "$LOG_FILE" 2>&1; then
      log "rebuild OK"
    else
      log "rebuild FAILED"
    fi

    log "update complete"
  fi
  sleep 10
done
