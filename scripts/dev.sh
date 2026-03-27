#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export BOAN_ORG_ID="${BOAN_ORG_ID:-dev-org}"

COMPOSE_FILE="$ROOT/src/docker-compose.dev.yml"

if [ ! -f "$COMPOSE_FILE" ]; then
  echo "docker-compose.dev.yml not found at $COMPOSE_FILE"
  exit 1
fi

if ! command -v docker &>/dev/null; then
  echo "docker is required"
  exit 1
fi

if ! docker compose version &>/dev/null 2>&1; then
  if command -v docker-compose &>/dev/null; then
    docker-compose -f "$COMPOSE_FILE" up --build "$@"
    exit $?
  fi
  echo "docker compose plugin not found"
  exit 1
fi

docker compose -f "$COMPOSE_FILE" up --build "$@"
