#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/src/packages"
REGISTRY="${BOAN_REGISTRY:-boanclaw}"
TAG="${BOAN_TAG:-latest}"
ERRORS=0

build_go() {
  local pkg=$1
  if [ ! -d "$SRC/$pkg" ]; then
    echo "  skip $pkg (directory not found)"
    return 0
  fi
  if [ ! -f "$SRC/$pkg/go.mod" ]; then
    echo "  skip $pkg (no go.mod)"
    return 0
  fi
  echo "▶ building $pkg"
  (cd "$SRC/$pkg" && go build ./...) || { echo "  FAIL $pkg"; ERRORS=$((ERRORS+1)); }
}

build_ts() {
  local pkg=$1
  if [ ! -d "$SRC/$pkg" ]; then
    echo "  skip $pkg (directory not found)"
    return 0
  fi
  if [ ! -f "$SRC/$pkg/package.json" ]; then
    echo "  skip $pkg (no package.json)"
    return 0
  fi
  echo "▶ building $pkg (ts)"
  (cd "$SRC/$pkg" && npm ci --prefer-offline 2>/dev/null && npm run build) || { echo "  FAIL $pkg"; ERRORS=$((ERRORS+1)); }
}

build_image() {
  local pkg=$1
  if [ ! -f "$SRC/$pkg/Dockerfile" ]; then
    echo "  skip $pkg image (no Dockerfile)"
    return 0
  fi
  echo "▶ docker build $pkg"
  docker build -t "$REGISTRY/$pkg:$TAG" "$SRC/$pkg" || { echo "  FAIL $pkg image"; ERRORS=$((ERRORS+1)); }
}

go_packages=(boan-proxy boan-policy-server boan-whitelist-proxy boan-llm-registry boan-credential-filter boan-audit-agent boan-onecli)
ts_packages=(boan-agent boan-admin-console)

if command -v go &>/dev/null; then
  for pkg in "${go_packages[@]}"; do
    build_go "$pkg"
  done
else
  echo "  go not found, skipping Go packages"
fi

if command -v node &>/dev/null; then
  for pkg in "${ts_packages[@]}"; do
    build_ts "$pkg"
  done
else
  echo "  node not found, skipping TS packages"
fi

if [ "${BUILD_IMAGES:-false}" = "true" ]; then
  if command -v docker &>/dev/null; then
    image_packages=(boan-proxy boan-policy-server boan-whitelist-proxy boan-llm-registry boan-credential-filter boan-audit-agent boan-onecli boan-asset-constitution boan-admin-console boan-sandbox)
    for pkg in "${image_packages[@]}"; do
      build_image "$pkg"
    done
  else
    echo "  docker not found, skipping image builds"
  fi
fi

if [ $ERRORS -gt 0 ]; then
  echo "build completed with $ERRORS error(s)"
  exit 1
fi
echo "build complete"
