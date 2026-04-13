#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$ROOT/deploy/config/gcp.env}"

if [[ -f "$CONFIG_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
fi

if [[ -n "${BOAN_GCP_SERVICE_ACCOUNT_KEY_PATH:-}" ]]; then
  export GOOGLE_APPLICATION_CREDENTIALS="$BOAN_GCP_SERVICE_ACCOUNT_KEY_PATH"
fi

PROJECT_ID="${PROJECT_ID:-${GCP_PROJECT_ID:-ai-security-test-473701}}"
PROJECT_NAME="${PROJECT_NAME:-${GCP_PROJECT_NAME:-ai-security-test}}"
REGION="${REGION:-${GCP_REGION:-asia-northeast3}}"
ORG_ID="${ORG_ID:-${BOAN_ORG_ID:-sds-corp}}"
POLICY_IMAGE="${POLICY_IMAGE:-${POLICY_SERVER_IMAGE:-gcr.io/${PROJECT_ID}/boan-policy-server:latest}}"
ADMIN_IMAGE="${ADMIN_IMAGE:-${ADMIN_API_IMAGE:-gcr.io/${PROJECT_ID}/boan-proxy:latest}}"
ENABLE_FIREBASE_HOSTING_VALUE="${ENABLE_FIREBASE_HOSTING_VALUE:-${ENABLE_FIREBASE_HOSTING:-false}}"
OAUTH_CLIENT_ID_VALUE="${OAUTH_CLIENT_ID_VALUE:-${BOAN_OAUTH_CLIENT_ID:-}}"
OAUTH_CLIENT_SECRET_VALUE="${OAUTH_CLIENT_SECRET_VALUE:-${BOAN_OAUTH_CLIENT_SECRET:-}}"
OAUTH_REDIRECT_URL_VALUE="${OAUTH_REDIRECT_URL_VALUE:-${BOAN_OAUTH_REDIRECT_URL:-}}"
APP_BASE_URL_VALUE="${APP_BASE_URL_VALUE:-${BOAN_APP_BASE_URL:-}}"
ALLOWED_EMAIL_DOMAINS_VALUE="${ALLOWED_EMAIL_DOMAINS_VALUE:-${BOAN_ALLOWED_EMAIL_DOMAINS:-}}"
OWNER_EMAIL_VALUE="${OWNER_EMAIL_VALUE:-${BOAN_OWNER_EMAIL:-}}"
JWT_SECRET_VALUE="${JWT_SECRET_VALUE:-${BOAN_JWT_SECRET:-}}"
GCP_ORG_RUNTIME_ID="${GCP_ORG_RUNTIME_ID:-${BOAN_GCP_ORG_ID:-}}"
ADMIN_EMAILS_VALUE="${ADMIN_EMAILS_VALUE:-${BOAN_ADMIN_EMAILS:-}}"
ALLOWED_SSO_VALUE="${ALLOWED_SSO_VALUE:-${BOAN_ALLOWED_SSO:-email_otp}}"
SMTP_HOST_VALUE="${SMTP_HOST_VALUE:-${BOAN_SMTP_HOST:-}}"
SMTP_PORT_VALUE="${SMTP_PORT_VALUE:-${BOAN_SMTP_PORT:-587}}"
SMTP_USER_VALUE="${SMTP_USER_VALUE:-${BOAN_SMTP_USER:-}}"
SMTP_PASSWORD_VALUE="${SMTP_PASSWORD_VALUE:-${BOAN_SMTP_PASSWORD:-}}"
SMTP_FROM_VALUE="${SMTP_FROM_VALUE:-${BOAN_SMTP_FROM:-}}"
WORKSTATION_PROVIDER_VALUE="${WORKSTATION_PROVIDER_VALUE:-${BOAN_WORKSTATION_PROVIDER:-gcp-compute}}"
WORKSTATION_PLATFORM_VALUE="${WORKSTATION_PLATFORM_VALUE:-${BOAN_WORKSTATION_PLATFORM:-windows}}"
WORKSTATION_REGION_VALUE="${WORKSTATION_REGION_VALUE:-${BOAN_WORKSTATION_REGION:-asia-northeast3}}"
WORKSTATION_MACHINE_TYPE_VALUE="${WORKSTATION_MACHINE_TYPE_VALUE:-${BOAN_WORKSTATION_MACHINE_TYPE:-e2-standard-2}}"
WORKSTATION_PROJECT_ID_VALUE="${WORKSTATION_PROJECT_ID_VALUE:-${BOAN_WORKSTATION_PROJECT_ID:-${PROJECT_ID}}}"
WORKSTATION_ZONE_VALUE="${WORKSTATION_ZONE_VALUE:-${BOAN_WORKSTATION_ZONE:-asia-northeast3-a}}"
WORKSTATION_IMAGE_PROJECT_VALUE="${WORKSTATION_IMAGE_PROJECT_VALUE:-${BOAN_WORKSTATION_IMAGE_PROJECT:-windows-cloud}}"
WORKSTATION_IMAGE_FAMILY_VALUE="${WORKSTATION_IMAGE_FAMILY_VALUE:-${BOAN_WORKSTATION_IMAGE_FAMILY:-windows-2022}}"
WORKSTATION_SUBNETWORK_VALUE="${WORKSTATION_SUBNETWORK_VALUE:-${BOAN_WORKSTATION_SUBNETWORK:-}}"
WORKSTATION_NETWORK_TAGS_VALUE="${WORKSTATION_NETWORK_TAGS_VALUE:-${BOAN_WORKSTATION_NETWORK_TAGS:-}}"
WORKSTATION_RDP_SOURCE_RANGES_VALUE="${WORKSTATION_RDP_SOURCE_RANGES_VALUE:-${BOAN_WORKSTATION_RDP_SOURCE_RANGES:-}}"
WORKSTATION_SERVICE_ACCOUNT_VALUE="${WORKSTATION_SERVICE_ACCOUNT_VALUE:-${BOAN_WORKSTATION_SERVICE_ACCOUNT:-}}"
WORKSTATION_ROOT_VOLUME_GIB_VALUE="${WORKSTATION_ROOT_VOLUME_GIB_VALUE:-${BOAN_WORKSTATION_ROOT_VOLUME_GIB:-100}}"
WORKSTATION_CONSOLE_BASE_URL_VALUE="${WORKSTATION_CONSOLE_BASE_URL_VALUE:-${BOAN_WORKSTATION_CONSOLE_BASE_URL:-}}"
WORKSTATION_WEB_BASE_URL_VALUE="${WORKSTATION_WEB_BASE_URL_VALUE:-${BOAN_WORKSTATION_WEB_BASE_URL:-}}"

if [[ -n "${WORKSTATION_RDP_SOURCE_RANGES_VALUE}" ]]; then
  WORKSTATION_RDP_SOURCE_RANGES_TF="[\"${WORKSTATION_RDP_SOURCE_RANGES_VALUE//,/\",\"}\"]"
else
  WORKSTATION_RDP_SOURCE_RANGES_TF="[]"
fi

POLICY_DIR="$ROOT/src/packages/boan-policy-server"
PROXY_DIR="$ROOT/src/packages/boan-proxy"
TF_DIR="$ROOT/deploy/terraform/envs/gcp"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing command: $1" >&2
    exit 1
  }
}

require_cmd gcloud
require_cmd terraform

ACTIVE_ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null || true)"
if [[ -z "$ACTIVE_ACCOUNT" ]]; then
  echo "No active gcloud account. Run: gcloud auth login" >&2
  exit 1
fi

echo "Using gcloud account: $ACTIVE_ACCOUNT"
echo "Project: $PROJECT_ID"
echo "Name:    $PROJECT_NAME"
echo "Region:  $REGION"
echo "Org ID:  $ORG_ID"
echo "Policy:  $POLICY_IMAGE"
echo "Admin:   $ADMIN_IMAGE"

gcloud config set project "$PROJECT_ID" >/dev/null

echo "Building policy server image..."
(
  cd "$POLICY_DIR"
  gcloud builds submit --project="$PROJECT_ID" --tag "$POLICY_IMAGE"
)

echo "Building admin api image..."
(
  cd "$PROXY_DIR"
  gcloud builds submit --project="$PROJECT_ID" --tag "$ADMIN_IMAGE"
)

echo "Preparing terraform variables..."
(
  cd "$TF_DIR"
  cat > terraform.tfvars <<EOF
project_id          = "${PROJECT_ID}"
project_name        = "${PROJECT_NAME}"
region              = "${REGION}"
org_id              = "${ORG_ID}"
policy_server_image = "${POLICY_IMAGE}"
admin_api_image     = "${ADMIN_IMAGE}"
enable_firebase_hosting = ${ENABLE_FIREBASE_HOSTING_VALUE}
oauth_client_id     = "${OAUTH_CLIENT_ID_VALUE}"
oauth_client_secret = "${OAUTH_CLIENT_SECRET_VALUE}"
oauth_redirect_url  = "${OAUTH_REDIRECT_URL_VALUE}"
app_base_url        = "${APP_BASE_URL_VALUE}"
allowed_email_domains = "${ALLOWED_EMAIL_DOMAINS_VALUE}"
owner_email         = "${OWNER_EMAIL_VALUE}"
jwt_secret          = "${JWT_SECRET_VALUE}"
gcp_org_id          = "${GCP_ORG_RUNTIME_ID}"
admin_emails        = "${ADMIN_EMAILS_VALUE}"
allowed_sso         = "${ALLOWED_SSO_VALUE}"
smtp_host           = "${SMTP_HOST_VALUE}"
smtp_port           = "${SMTP_PORT_VALUE}"
smtp_user           = "${SMTP_USER_VALUE}"
smtp_password       = "${SMTP_PASSWORD_VALUE}"
smtp_from           = "${SMTP_FROM_VALUE}"
workstation_provider = "${WORKSTATION_PROVIDER_VALUE}"
workstation_platform = "${WORKSTATION_PLATFORM_VALUE}"
workstation_region   = "${WORKSTATION_REGION_VALUE}"
workstation_machine_type = "${WORKSTATION_MACHINE_TYPE_VALUE}"
workstation_project_id = "${WORKSTATION_PROJECT_ID_VALUE}"
workstation_zone = "${WORKSTATION_ZONE_VALUE}"
workstation_image_project = "${WORKSTATION_IMAGE_PROJECT_VALUE}"
workstation_image_family = "${WORKSTATION_IMAGE_FAMILY_VALUE}"
workstation_subnetwork = "${WORKSTATION_SUBNETWORK_VALUE}"
workstation_network_tags = "${WORKSTATION_NETWORK_TAGS_VALUE}"
workstation_rdp_source_ranges = ${WORKSTATION_RDP_SOURCE_RANGES_TF}
workstation_service_account = "${WORKSTATION_SERVICE_ACCOUNT_VALUE}"
workstation_root_volume_gib = "${WORKSTATION_ROOT_VOLUME_GIB_VALUE}"
workstation_console_base_url = "${WORKSTATION_CONSOLE_BASE_URL_VALUE}"
workstation_web_base_url = "${WORKSTATION_WEB_BASE_URL_VALUE}"
EOF
)

echo "Applying terraform..."
(
  cd "$TF_DIR"
  terraform init
  terraform apply -auto-approve
)

echo "Generating/loading org token..."
TOKEN_FILE="$ROOT/deploy/config/${ORG_ID}.token"
mkdir -p "$(dirname "$TOKEN_FILE")"
if [[ -s "$TOKEN_FILE" ]]; then
  ORG_TOKEN="$(cat "$TOKEN_FILE")"
else
  ORG_TOKEN="$(openssl rand -hex 32)"
  echo "$ORG_TOKEN" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
fi

POLICY_SERVICE_NAME="boan-policy-server-${ORG_ID}"
echo "Injecting BOAN_ORG_TOKEN into Cloud Run service ${POLICY_SERVICE_NAME}..."
gcloud run services update "${POLICY_SERVICE_NAME}" \
  --project="$PROJECT_ID" --region="$REGION" \
  --update-env-vars="BOAN_ORG_TOKEN=${ORG_TOKEN}" >/dev/null

echo ""
echo "========================================================"
echo "  ORG:   ${ORG_ID}"
echo "  TOKEN: ${ORG_TOKEN}"
echo "  (saved to ${TOKEN_FILE} — hand to users during install)"
echo "========================================================"
echo ""
echo "Deployment complete."
echo "Cloud Run services:"
gcloud run services list --project="$PROJECT_ID" --region="$REGION"
