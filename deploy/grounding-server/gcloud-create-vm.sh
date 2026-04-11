#!/usr/bin/env bash
# GCP VM 생성 (g2-standard-4 + L4 spot, Deep Learning Image).
# 한 번만 실행해서 인스턴스 만들고, SSH 들어가서 bootstrap.sh 돌리는 흐름.
#
# 사용법:
#   PROJECT=my-project REGION=us-central1 bash gcloud-create-vm.sh
#   PROJECT=my-project REGION=asia-northeast3 ZONE=asia-northeast3-a bash gcloud-create-vm.sh
set -euo pipefail

PROJECT="${PROJECT:?set PROJECT=your-gcp-project}"
REGION="${REGION:-us-central1}"
ZONE="${ZONE:-${REGION}-a}"
INSTANCE_NAME="${INSTANCE_NAME:-boan-grounding}"
MACHINE_TYPE="${MACHINE_TYPE:-g2-standard-4}"
DISK_SIZE="${DISK_SIZE:-100}"
ACCELERATOR="${ACCELERATOR:-type=nvidia-l4,count=1}"
# Deep Learning VM (Debian 11, CUDA 12.x). 다른 OS 필요하면 IMAGE_FAMILY 변경.
IMAGE_FAMILY="${IMAGE_FAMILY:-common-cu123-debian-11}"
IMAGE_PROJECT="${IMAGE_PROJECT:-deeplearning-platform-release}"
PROVISIONING_MODEL="${PROVISIONING_MODEL:-SPOT}"   # SPOT (싸지만 종료 가능) | STANDARD
PREEMPTIBLE_FLAG=""
if [[ "$PROVISIONING_MODEL" == "SPOT" ]]; then
  PREEMPTIBLE_FLAG="--provisioning-model=SPOT --instance-termination-action=STOP"
fi

# 본체 IP whitelist (안전을 위해 0.0.0.0/0 노출 금지 권장)
SOURCE_RANGES="${SOURCE_RANGES:-0.0.0.0/0}"

echo "▶ creating instance:"
echo "    project   : $PROJECT"
echo "    zone      : $ZONE"
echo "    machine   : $MACHINE_TYPE + L4 (spot=$([ "$PROVISIONING_MODEL" == "SPOT" ] && echo yes || echo no))"
echo "    image     : $IMAGE_FAMILY ($IMAGE_PROJECT)"

gcloud compute instances create "$INSTANCE_NAME" \
  --project="$PROJECT" \
  --zone="$ZONE" \
  --machine-type="$MACHINE_TYPE" \
  --accelerator="$ACCELERATOR" \
  --image-family="$IMAGE_FAMILY" \
  --image-project="$IMAGE_PROJECT" \
  --boot-disk-size="${DISK_SIZE}GB" \
  --boot-disk-type=pd-balanced \
  --maintenance-policy=TERMINATE \
  --metadata="install-nvidia-driver=True" \
  --tags=boan-grounding \
  $PREEMPTIBLE_FLAG

echo "▶ creating firewall rule (TCP 8000 from $SOURCE_RANGES)"
gcloud compute firewall-rules create boan-grounding-allow-8000 \
  --project="$PROJECT" \
  --direction=INGRESS \
  --action=ALLOW \
  --rules=tcp:8000 \
  --source-ranges="$SOURCE_RANGES" \
  --target-tags=boan-grounding 2>/dev/null || echo "  (rule already exists, skipping)"

echo ""
echo "✅ instance created"
echo ""
echo "▶ next steps:"
echo ""
echo "  1) wait ~2 min for nvidia driver auto-install to finish, then SSH:"
echo "     gcloud compute ssh $INSTANCE_NAME --project=$PROJECT --zone=$ZONE"
echo ""
echo "  2) on the VM, run:"
echo "     curl -fsSL https://raw.githubusercontent.com/<YOUR_REPO>/main/deploy/grounding-server/bootstrap.sh | sudo bash"
echo "     # OR scp the bootstrap.sh from this repo and run it"
echo ""
echo "  3) get the external IP:"
echo "     gcloud compute instances describe $INSTANCE_NAME --project=$PROJECT --zone=$ZONE \\"
echo "       --format='get(networkInterfaces[0].accessConfigs[0].natIP)'"
echo ""
echo "  4) register that IP:8000 in BoanClaw LLM Registry → 이미지 모델 → GUI role"
