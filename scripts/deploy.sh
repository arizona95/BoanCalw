#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT/src/packages"
REGISTRY="${BOAN_REGISTRY:-boanclaw}"
TAG="${BOAN_TAG:-latest}"
K8S_DIR="$ROOT/src/k8s"

IMAGES=(
  boan-proxy
  boan-policy-server
  boan-whitelist-proxy
  boan-llm-registry
  boan-credential-filter
  boan-audit-agent
  boan-onecli
  boan-asset-constitution
  boan-admin-console
  boan-sandbox
)

echo "▶ tagging and pushing images"
for img in "${IMAGES[@]}"; do
  if docker image inspect "$REGISTRY/$img:$TAG" &>/dev/null; then
    echo "  push $img:$TAG"
    docker push "$REGISTRY/$img:$TAG"
  else
    echo "  skip $img (image not found locally)"
  fi
done

if ! command -v kubectl &>/dev/null; then
  echo "kubectl not found, skipping k8s deployment"
  exit 0
fi

echo "▶ applying k8s manifests"
kubectl apply -f "$K8S_DIR/namespace.yaml"
kubectl apply -f "$K8S_DIR/network-policy.yaml"
kubectl apply -f "$K8S_DIR/pods/"

DEPLOYMENTS=(
  boan-proxy
  boan-policy-server
  boan-credential-filter
  boan-audit-agent
  boan-onecli
  boan-asset-constitution
  boan-llm-registry
  boan-whitelist-proxy
  boan-admin-console
  boan-sandbox
)

echo "▶ waiting for rollouts"
for dep in "${DEPLOYMENTS[@]}"; do
  if kubectl get deployment "$dep" -n boan &>/dev/null 2>&1; then
    echo "  waiting for $dep..."
    kubectl rollout status "deployment/$dep" -n boan --timeout=120s || echo "  timeout: $dep"
  fi
done

echo "deploy complete"
