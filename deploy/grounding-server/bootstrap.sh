#!/usr/bin/env bash
# BoanClaw Grounding Server bootstrap.
# 사용법:
#   sudo bash bootstrap.sh                                  # 기본: MAI-UI-8B
#   sudo MODEL=osunlp/UGround-V1-2B bash bootstrap.sh       # 다른 모델
#   sudo MODEL=tencent/POINTS-GUI-G PORT=8000 bash bootstrap.sh
set -euo pipefail

MODEL="${MODEL:-Tongyi-MAI/MAI-UI-8B}"
PORT="${PORT:-8000}"
SERVED_NAME="${SERVED_NAME:-grounding}"
GPU_MEMORY_UTILIZATION="${GPU_MEMORY_UTILIZATION:-0.85}"
MAX_MODEL_LEN="${MAX_MODEL_LEN:-8192}"
DTYPE="${DTYPE:-bfloat16}"

echo "▶ MODEL=$MODEL"
echo "▶ PORT=$PORT"
echo "▶ DTYPE=$DTYPE"
echo "▶ MAX_MODEL_LEN=$MAX_MODEL_LEN"

# ── 1. 사전 도구 확인 ─────────────────────────────────────────────
if ! command -v docker >/dev/null 2>&1; then
  echo "▶ installing docker"
  curl -fsSL https://get.docker.com | sh
  systemctl enable --now docker
fi

if ! docker info 2>&1 | grep -qi nvidia; then
  echo "▶ installing nvidia-container-toolkit"
  distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
  curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
    | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
  curl -s -L https://nvidia.github.io/libnvidia-container/$distribution/libnvidia-container.list \
    | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
    | tee /etc/apt/sources.list.d/nvidia-container-toolkit.list >/dev/null
  apt-get update
  apt-get install -y nvidia-container-toolkit
  nvidia-ctk runtime configure --runtime=docker
  systemctl restart docker
fi

# ── 2. 기존 컨테이너 정리 ─────────────────────────────────────────
if docker ps -a --format '{{.Names}}' | grep -q '^boan-grounding$'; then
  echo "▶ stopping previous boan-grounding container"
  docker rm -f boan-grounding >/dev/null 2>&1 || true
fi

# ── 3. vLLM 서버 컨테이너 기동 ────────────────────────────────────
# - --trust-remote-code: MAI-UI/Qwen3-VL 등 custom modeling 코드 허용
# - --enforce-eager: CUDA graph 비활성 (vision 모델 호환성)
# - HF cache 는 /opt/hfcache 에 영구 마운트 → 재시작 시 모델 재다운로드 안 함
mkdir -p /opt/hfcache

echo "▶ starting vLLM with model=$MODEL"
docker run -d \
  --name boan-grounding \
  --restart unless-stopped \
  --gpus all \
  --ipc=host \
  -p ${PORT}:8000 \
  -v /opt/hfcache:/root/.cache/huggingface \
  -e HF_HUB_ENABLE_HF_TRANSFER=1 \
  vllm/vllm-openai:latest \
  --model "$MODEL" \
  --served-model-name "$SERVED_NAME" \
  --host 0.0.0.0 \
  --port 8000 \
  --dtype "$DTYPE" \
  --max-model-len "$MAX_MODEL_LEN" \
  --gpu-memory-utilization "$GPU_MEMORY_UTILIZATION" \
  --trust-remote-code \
  --enforce-eager

# ── 4. systemd unit (vLLM 컨테이너 자동 복구) ─────────────────────
cat > /etc/systemd/system/boan-grounding.service <<EOF
[Unit]
Description=BoanClaw Grounding Server (vLLM)
Requires=docker.service
After=docker.service

[Service]
Type=simple
ExecStart=/usr/bin/docker start -a boan-grounding
ExecStop=/usr/bin/docker stop -t 30 boan-grounding
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable boan-grounding

echo ""
echo "✅ boan-grounding started"
echo ""
echo "▶ test:"
echo "  curl -s http://localhost:${PORT}/v1/models | python3 -m json.tool"
echo ""
echo "▶ logs:"
echo "  docker logs -f boan-grounding"
echo ""
echo "▶ to switch models later:"
echo "  sudo MODEL=other/model bash $(realpath $0)"
