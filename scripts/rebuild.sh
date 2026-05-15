#!/usr/bin/env bash
# boan-proxy 코드는 boan-sandbox에 내장되므로 항상 함께 빌드해야 합니다.
# 사용법: scripts/rebuild.sh [추가서비스...]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="$ROOT/docker-compose.dev.yml"

# boan-proxy 변경 시 반드시 boan-sandbox도 함께 빌드
ALWAYS_TOGETHER=(boan-proxy boan-sandbox boan-admin-console)

EXTRA=("$@")
ALL=("${ALWAYS_TOGETHER[@]}" "${EXTRA[@]}")

# 중복 제거
declare -A seen
TARGETS=()
for svc in "${ALL[@]}"; do
  if [[ -z "${seen[$svc]+_}" ]]; then
    seen[$svc]=1
    TARGETS+=("$svc")
  fi
done

echo "▶ building: ${TARGETS[*]}"
docker compose -f "$COMPOSE_FILE" build "${TARGETS[@]}"

echo "▶ restarting: ${TARGETS[*]}"
docker compose -f "$COMPOSE_FILE" up -d --force-recreate "${TARGETS[@]}"

# Volume bind from host can come up with 1000:1000 ownership which the boan
# UID inside the proxy/sandbox containers can't read. The image entrypoint
# tries to chown but on some hosts that silently fails before the proxy
# binary starts. Reassert from the host as the simplest reliable path.
if docker ps --format '{{.Names}}' | grep -q '^boanclaw-boan-proxy-1$'; then
  # standalone proxy UID 100 vs sandbox-embedded proxy UID 1000 both share
  # /data/users; loosen mode so either process can write. (host-only file in
  # docker volume, not exposed to other systems.)
  docker exec -u 0 boanclaw-boan-proxy-1 \
    sh -c 'chmod 777 /data/users 2>/dev/null; chmod 666 /data/users/*.json 2>/dev/null' \
    >/dev/null 2>&1 || true
fi
if docker ps --format '{{.Names}}' | grep -q '^boanclaw-boan-sandbox-1$'; then
  docker exec -u 0 boanclaw-boan-sandbox-1 \
    sh -c 'chmod 777 /data/users 2>/dev/null; chmod 666 /data/users/*.json 2>/dev/null' \
    >/dev/null 2>&1 || true
fi
# Restart proxy so it loads users.json with the corrected ownership.
docker restart boanclaw-boan-proxy-1 >/dev/null 2>&1 || true

echo "▶ waiting for services to be healthy..."
MAX_WAIT=60
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
  ALL_HEALTHY=true
  for svc in "${TARGETS[@]}"; do
    STATUS=$(docker compose -f "$COMPOSE_FILE" ps --format '{{.Status}}' "$svc" 2>/dev/null)
    case "$STATUS" in
      *healthy*) ;;
      *"Up"*)    ;; # no healthcheck defined
      *)         ALL_HEALTHY=false ;;
    esac
  done
  if $ALL_HEALTHY; then
    echo "✅ all services up and healthy (${ELAPSED}s)"
    # 빠른 연결 확인
    for svc in "${TARGETS[@]}"; do
      case "$svc" in
        boan-admin-console) curl -sf http://localhost:19080/ > /dev/null 2>&1 && echo "  ✓ admin-console :19080" || echo "  ✗ admin-console :19080 not responding" ;;
        boan-computer-use)  curl -sf http://localhost:8090/healthz > /dev/null 2>&1 && echo "  ✓ computer-use  :8090"  || echo "  ✗ computer-use  :8090 not responding" ;;
      esac
    done
    exit 0
  fi
  sleep 2
  ELAPSED=$((ELAPSED+2))
  printf "\r  %ds / %ds..." "$ELAPSED" "$MAX_WAIT"
done
echo ""
echo "⚠️  timeout (${MAX_WAIT}s) — some services may not be ready:"
docker compose -f "$COMPOSE_FILE" ps "${TARGETS[@]}"
