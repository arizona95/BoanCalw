#!/bin/sh
# ════════════════════════════════════════════════════════════════════════
# BoanClaw Kill Chain — Wazuh active-response webhook script.
#
# 호출 방식 (Wazuh AR/3 protocol):
#   stdin 에 alert JSON 한 줄.
#   .parameters.alert.data.win.eventdata.image / processName / agent.name 등에서
#   process_name 과 target email 추출 → boan-proxy /api/kill-chain/event 로 POST.
#
# boan-proxy 가 받으면:
#   1) MatchProcess(process_name) → rule 매칭
#   2) auto=true 면 즉시 발동 (네트워크 격리 → forensic disk snapshot → STOP → DELETE)
#   3) auto=false 면 incident 만 pending-manual 로 기록 (HITL 페이지에서 관리자 확인)
#
# 환경변수 (manager 측에서 ossec.conf 에 export 또는 wrapper 로 주입):
#   BOAN_PROXY_WEBHOOK   — http://<admin-host>:19080/api/kill-chain/event (필수)
#   BOAN_AGENT_EMAIL_MAP — JSON {"agent_name": "user@email"} (선택). 없으면 agent 의 hostname 사용.
# ════════════════════════════════════════════════════════════════════════

set -u

LOG=/var/ossec/logs/active-responses.log
WEBHOOK="${BOAN_PROXY_WEBHOOK:-http://host.docker.internal:19080/api/kill-chain/event}"
TIMEOUT=5

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] [boan-killchain] $*" >> "$LOG"; }

# Wazuh AR protocol — alert JSON arrives on stdin (single line).
# Some wazuh-execd builds pass the JSON as argv[1] instead of stdin
# (observed on 4.7.5: stdin empty, argv contains the message). Try both.
INPUT=$(cat 2>/dev/null || true)
if [ -z "$INPUT" ] && [ "$#" -gt 0 ]; then
  INPUT="$*"
fi
log "AR invoked (stdin_or_argv_len=$(printf '%s' "$INPUT" | wc -c | tr -d ' ') argc=$#)"
if [ -z "$INPUT" ]; then
  log "no stdin or argv input — skipping"
  exit 0
fi

# Action 종류: add | delete (Wazuh 가 trigger 시 add, timeout 만료 시 delete).
# 우리는 add 만 처리 — delete 는 noop.
ACTION=$(printf '%s' "$INPUT" | sed -n 's/.*"command":"\([^"]*\)".*/\1/p' | head -1)
case "$ACTION" in
add|"") : ;;
delete) log "ignoring delete event"; exit 0 ;;
esac

# 핵심 필드 추출 — sed grep 단순. jq 가 없는 환경 (alpine wazuh-agent) 도 OK.
extract() {
  printf '%s' "$INPUT" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" | head -1
}

PROCESS=$(extract "image")
[ -z "$PROCESS" ] && PROCESS=$(extract "processName")
[ -z "$PROCESS" ] && PROCESS=$(extract "process_name")
# windows path → basename + lower.
PROCESS=$(printf '%s' "$PROCESS" | sed 's|^.*[\\/]||' | tr 'A-Z' 'a-z' | sed 's/\.exe$//')

AGENT_NAME=$(extract "agent_name")
# Wazuh AR/3 JSON has agent.name nested: "agent":{"id":"006","name":"...",...}
# Extract specifically the agent block's name to avoid matching decoder.name etc.
[ -z "$AGENT_NAME" ] && AGENT_NAME=$(printf '%s' "$INPUT" | sed -n 's/.*"agent":{[^}]*"name":"\([^"]*\)".*/\1/p' | head -1)
[ -z "$AGENT_NAME" ] && AGENT_NAME=$(printf '%s' "$INPUT" | sed -n 's/.*"name":"\([^"]*\)".*/\1/p' | head -1)

# Agent VM hostname → user email local-part.
# Convention: VM is named "boan-win-<user>" where <user> is the email local-part
# with dots replaced by dashes (Windows NetBIOS forbids dots).
# Example: "boan-win-genaisec-ssc" → local-part "genaisec.ssc"
USER_LOCAL=$(printf '%s' "$AGENT_NAME" | sed 's/^boan-win-//' | tr '-' '.')

# 1) BOAN_AGENT_EMAIL_MAP env override (key = agent_name as reported, before transform).
if [ -n "${BOAN_AGENT_EMAIL_MAP:-}" ]; then
  EMAIL=$(printf '%s' "$BOAN_AGENT_EMAIL_MAP" | sed -n "s/.*\"$AGENT_NAME\":\"\([^\"]*\)\".*/\1/p" | head -1)
fi
# 2) BOAN_DEFAULT_EMAIL_DOMAIN + transformed local-part.
if [ -z "${EMAIL:-}" ] && [ -n "${BOAN_DEFAULT_EMAIL_DOMAIN:-}" ] && ! echo "$USER_LOCAL" | grep -q '@'; then
  EMAIL="${USER_LOCAL}@${BOAN_DEFAULT_EMAIL_DOMAIN}"
fi
# 3) Last-resort fallback.
[ -z "${EMAIL:-}" ] && EMAIL="$USER_LOCAL"

if [ -z "$PROCESS" ]; then
  log "no process_name parsed — skipping"
  exit 0
fi

log "agent=$AGENT_NAME process=$PROCESS email=$EMAIL → POST $WEBHOOK"

# Keep payload minimal — boan-proxy only needs process_name + target_email.
# raw_alert was producing invalid JSON due to backslash/control-char escaping bugs.
PAYLOAD=$(printf '{"process_name":"%s","target_email":"%s"}' "$PROCESS" "$EMAIL")

RESP=$(curl -sS --max-time "$TIMEOUT" -X POST -H 'Content-Type: application/json' \
  --data "$PAYLOAD" "$WEBHOOK" 2>&1) || RESP="curl error: $RESP"
log "response: $(printf '%s' "$RESP" | tr -d '\n' | cut -c1-300)"
exit 0
