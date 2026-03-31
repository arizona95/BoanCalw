#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${CONFIG_FILE:-$ROOT/deploy/config/gcp.env}"

if [[ -f "$CONFIG_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
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
ALLOWED_SSO_VALUE="${ALLOWED_SSO_VALUE:-${BOAN_ALLOWED_SSO:-google,email_otp}}"
SMTP_HOST_VALUE="${SMTP_HOST_VALUE:-${BOAN_SMTP_HOST:-}}"
SMTP_PORT_VALUE="${SMTP_PORT_VALUE:-${BOAN_SMTP_PORT:-587}}"
SMTP_USER_VALUE="${SMTP_USER_VALUE:-${BOAN_SMTP_USER:-}}"
SMTP_PASSWORD_VALUE="${SMTP_PASSWORD_VALUE:-${BOAN_SMTP_PASSWORD:-}}"
SMTP_FROM_VALUE="${SMTP_FROM_VALUE:-${BOAN_SMTP_FROM:-}}"

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
EOF
)

echo "Applying terraform..."
(
  cd "$TF_DIR"
  terraform init
  terraform apply -auto-approve
)

echo "Deployment complete."
echo "Cloud Run services:"
gcloud run services list --project="$PROJECT_ID" --region="$REGION"
