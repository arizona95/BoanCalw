#!/usr/bin/env bash
# update-watcher.sh - host-side daemon
# 1) Polls GitHub API every 30min for latest version → writes .boanclaw-latest
# 2) Watches trigger file every 10s → runs git pull + rebuild when triggered
set -euo pipefail

INSTALL_DIR="${1:-$HOME/boanclaw}"
TRIGGER_FILE="/tmp/boanclaw-triggers/update-requested"
LATEST_FILE="$INSTALL_DIR/.boanclaw-latest"
LOG_FILE="/tmp/boanclaw-update.log"
REPO_API="https://api.github.com/repos/arizona95/BoanCalw/commits/main"
CHECK_INTERVAL=1800  # 30 minutes
POLL_INTERVAL=10     # 10 seconds

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"; }

check_latest() {
  local sha
  sha=$(curl -sf "$REPO_API" 2>/dev/null | grep '"sha"' | head -1 | sed 's/.*"sha": *"\([a-f0-9]*\)".*/\1/' | cut -c1-7)
  if [ -n "$sha" ]; then
    echo "$sha" > "$LATEST_FILE"
    log "latest version check: $sha"
  fi
}

log "update-watcher started (install_dir=$INSTALL_DIR)"

# initial version check
check_latest
LAST_CHECK=$(date +%s)

while true; do
  # periodic version check (every 30 min)
  NOW=$(date +%s)
  if [ $((NOW - LAST_CHECK)) -ge $CHECK_INTERVAL ]; then
    check_latest
    LAST_CHECK=$NOW
  fi

  # trigger file check (every 10s)
  if [ -f "$TRIGGER_FILE" ]; then
    log "update triggered"
    rm -f "$TRIGGER_FILE"

    cd "$INSTALL_DIR"

    if git pull --ff-only >> "$LOG_FILE" 2>&1; then
      log "git pull OK"
    else
      log "git pull failed, trying rebase"
      git pull --rebase >> "$LOG_FILE" 2>&1 || { log "git pull failed"; continue; }
    fi

    git rev-parse --short HEAD > "$INSTALL_DIR/.boanclaw-version"
    log "version updated to $(cat "$INSTALL_DIR/.boanclaw-version")"

    check_latest

    log "starting rebuild..."
    if bash "$INSTALL_DIR/scripts/rebuild.sh" >> "$LOG_FILE" 2>&1; then
      log "rebuild OK"
    else
      log "rebuild FAILED"
    fi
    log "update complete"
  fi

  sleep $POLL_INTERVAL
done
