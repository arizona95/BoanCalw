#!/usr/bin/env bash
# 테스트: 서비스 상태 (D-1, D-2)
set -euo pipefail
source "$(dirname "$0")/test-helpers.sh"
echo "═══ 서비스 상태 테스트 ═══"

section "D-1: 서비스 헬스체크"
for svc in boan-proxy boan-sandbox boan-admin-console boan-credential-filter boan-policy-server boan-computer-use; do
  CNAME="boanclaw-${svc}-1"
  STATUS=$(docker inspect --format '{{.State.Status}}' "$CNAME" 2>/dev/null || echo "not found")
  if [ "$STATUS" = "running" ]; then
    pass "$svc — running"
  else
    fail "$svc — $STATUS"
  fi
done

section "D-1: HTTP 헬스체크"
for check in "admin-console:$API/:200" "credential-filter:http://localhost:8082/healthz:200"; do
  IFS=: read -r name url expected <<< "$check"
  CODE=$(curl -so /dev/null -w '%{http_code}' "$url" --connect-timeout 3 2>/dev/null || echo "000")
  [ "$CODE" != "000" ] && pass "$name HTTP $CODE" || fail "$name 연결 불가"
done

summary
