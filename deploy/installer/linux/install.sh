#!/usr/bin/env bash
set -euo pipefail

BOAN_VERSION="${BOAN_VERSION:-latest}"
REGISTRY="${BOAN_REGISTRY:-ghcr.io/samsung-sds/boanclaw}"
SYSTEMD_DIR="/etc/systemd/system"
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/boan"
DATA_DIR="/var/lib/boan"
COMPOSE_DIR="/opt/boanclaw"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[boan]${NC} $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC} $*"; }
error() { echo -e "${RED}[error]${NC} $*" >&2; exit 1; }

echo ""
echo "  ┌──────────────────────────────────────────┐"
echo "  │  BoanClaw Installer v${BOAN_VERSION}              │"
echo "  │  Samsung SDS AI Security                 │"
echo "  └──────────────────────────────────────────┘"
echo ""

command -v docker &>/dev/null || error "Docker is required. Install from https://docs.docker.com/engine/install/"
docker info &>/dev/null || error "Docker daemon is not running."

if ! docker compose version &>/dev/null && ! command -v docker-compose &>/dev/null; then
  error "Docker Compose is required. Install with: apt install docker-compose-plugin"
fi

: "${BOAN_ORG_ID:?Set BOAN_ORG_ID=<your-org-id>}"

sudo mkdir -p "$CONF_DIR" "$DATA_DIR" "$COMPOSE_DIR"

IMAGES=(
  boan-proxy
  boan-policy-server
  boan-credential-filter
  boan-audit-agent
  boan-asset-constitution
  boan-llm-registry
  boan-whitelist-proxy
  boan-admin-console
  boan-sandbox
)

for img in "${IMAGES[@]}"; do
  info "pulling $img..."
  docker pull "$REGISTRY/$img:$BOAN_VERSION" || warn "image $img not found in registry, skipping"
done

if [ ! -f "$CONF_DIR/ca.crt" ]; then
  info "generating CA certificate..."
  docker run --rm -v "$CONF_DIR:/out" \
    "$REGISTRY/boan-proxy:$BOAN_VERSION" \
    boan-proxy --gen-ca --ca-cert /out/ca.crt --ca-key /out/ca.key
fi

if command -v update-ca-certificates &>/dev/null; then
  sudo cp "$CONF_DIR/ca.crt" /usr/local/share/ca-certificates/boanclaw.crt
  sudo update-ca-certificates
elif command -v trust &>/dev/null; then
  sudo trust anchor "$CONF_DIR/ca.crt"
fi

info "generating docker-compose.yml..."
sudo tee "$COMPOSE_DIR/docker-compose.yml" > /dev/null << COMPOSEEOF
version: "3.9"

services:
  boan-proxy:
    image: ${REGISTRY}/boan-proxy:${BOAN_VERSION}
    ports:
      - "18080:18080"
      - "18081:18081"
    environment:
      - BOAN_ORG_ID=${BOAN_ORG_ID}
      - BOAN_POLICY_URL=http://boan-policy-server:8080
      - BOAN_CREDENTIAL_FILTER_URL=http://boan-credential-filter:8080
      - BOAN_AUDIT_URL=http://boan-audit-agent:8080
      - BOAN_LLM_REGISTRY_URL=http://boan-llm-registry:8080
      - BOAN_WHITELIST_PROXY_URL=http://boan-whitelist-proxy:8090
    volumes:
      - ${CONF_DIR}:/etc/boan:ro
    depends_on:
      - boan-policy-server
      - boan-credential-filter
      - boan-audit-agent
    networks:
      - boan-internal
    restart: unless-stopped

  boan-policy-server:
    image: ${REGISTRY}/boan-policy-server:${BOAN_VERSION}
    environment:
      - BOAN_ORG_ID=${BOAN_ORG_ID}
    volumes:
      - policy-data:/data/policies
      - policy-keys:/etc/boan-policy
    networks:
      - boan-internal
    restart: unless-stopped

  boan-credential-filter:
    image: ${REGISTRY}/boan-credential-filter:${BOAN_VERSION}
    environment:
      - BOAN_ORG_ID=${BOAN_ORG_ID}
    networks:
      - boan-internal
    restart: unless-stopped

  boan-audit-agent:
    image: ${REGISTRY}/boan-audit-agent:${BOAN_VERSION}
    environment:
      - BOAN_ORG_ID=${BOAN_ORG_ID}
    networks:
      - boan-internal
    restart: unless-stopped

  boan-asset-constitution:
    image: ${REGISTRY}/boan-asset-constitution:${BOAN_VERSION}
    environment:
      - BOAN_ORG_ID=${BOAN_ORG_ID}
      - BOAN_POLICY_URL=http://boan-policy-server:8080
    depends_on:
      - boan-policy-server
    networks:
      - boan-internal
    restart: unless-stopped

  boan-llm-registry:
    image: ${REGISTRY}/boan-llm-registry:${BOAN_VERSION}
    environment:
      - BOAN_ORG_ID=${BOAN_ORG_ID}
    networks:
      - boan-internal
    restart: unless-stopped

  boan-whitelist-proxy:
    image: ${REGISTRY}/boan-whitelist-proxy:${BOAN_VERSION}
    environment:
      - BOAN_ORG_ID=${BOAN_ORG_ID}
      - BOAN_LLM_URL=http://boan-llm-registry:8080
    depends_on:
      - boan-llm-registry
    networks:
      - boan-internal
    restart: unless-stopped

  boan-admin-console:
    image: ${REGISTRY}/boan-admin-console:${BOAN_VERSION}
    ports:
      - "18099:80"
    depends_on:
      - boan-policy-server
      - boan-audit-agent
      - boan-credential-filter
      - boan-llm-registry
    networks:
      - boan-internal
    restart: unless-stopped

networks:
  boan-internal:
    driver: bridge

volumes:
  policy-data:
  policy-keys:
COMPOSEEOF

info "installing boanclaw CLI..."
cat > /tmp/boanclaw << 'EOF'
#!/usr/bin/env bash
COMPOSE_DIR="/opt/boanclaw"
case "${1:-}" in
  start)   docker compose -f "$COMPOSE_DIR/docker-compose.yml" up -d ;;
  stop)    docker compose -f "$COMPOSE_DIR/docker-compose.yml" down ;;
  status)  docker compose -f "$COMPOSE_DIR/docker-compose.yml" ps ;;
  logs)    docker compose -f "$COMPOSE_DIR/docker-compose.yml" logs -f "${@:2}" ;;
  audit)   docker exec boan-proxy boan-audit "${@:2}" ;;
  *)       echo "usage: boanclaw {start|stop|status|logs|audit}" ;;
esac
EOF
sudo install -m 755 /tmp/boanclaw "$BIN_DIR/boanclaw"

info "starting BoanClaw stack..."
cd "$COMPOSE_DIR"
docker compose up -d

info "waiting for proxy to start..."
for i in $(seq 1 15); do
  curl -sf http://localhost:18081/healthz &>/dev/null && break
  sleep 2
done

for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
  if [ -f "$rc" ]; then
    grep -q "BOAN_PROXY" "$rc" || cat >> "$rc" << 'ENVEOF'

export HTTP_PROXY=http://localhost:18080
export HTTPS_PROXY=http://localhost:18080
ENVEOF
  fi
done

echo ""
echo "  BoanClaw installed successfully!"
echo ""
echo "  boanclaw start    — start stack"
echo "  boanclaw stop     — stop stack"
echo "  boanclaw status   — service status"
echo "  boanclaw logs     — view logs"
echo "  boanclaw audit    — security audit"
echo ""
echo "  Admin Console: http://localhost:18099"
echo ""
