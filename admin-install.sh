#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# BoanClaw — 관리자용 GCP 조직 배포 스크립트
#
# 이 스크립트는 **조직 1개를 GCP 위에 올리는** 일회성 관리자 작업입니다.
# 사용자용 한 줄 설치(install.sh) 와는 별개입니다.
#
# 전체 과정 (관리자가 처음 한 번만):
#   1) gcloud CLI 확인 / 설치 안내
#   2) gcloud auth login (브라우저 OAuth)
#   3) GCP 프로젝트 확인 — 없으면 생성 제안
#   4) 결제 계정 연결 확인
#   5) 필수 API 활성화 (Cloud Run / Compute / Secret Manager / IAM / CloudBuild)
#   6) IAM 역할 점검 (Project Owner 또는 Editor 권한 필요)
#   7) terraform / deploy_policy_server_gcp.sh 로 policy-server + org infra 배포
#   8) Org URL + Token 출력 → 사용자에게 한 줄 설치 명령과 함께 전달
#
# 사용:
#   # 대화형 (인자 없음) — 값 순서대로 물어봄
#   ./admin-install.sh
#
#   # 또는 인자/환경변수로 한 번에
#   ./admin-install.sh \
#     --project-id sds-boanclaw-prod \
#     --org-id sds-corp \
#     --owner-email admin@sds.com \
#     --region asia-northeast3 \
#     --allowed-email-domains samsung.com,samsungsds.com
#
# 전제조건: 브라우저 있는 Mac/Linux (gcloud auth login 수행 가능).
# 필수 도구: gcloud, terraform, openssl (대부분 자동 설치 안내).
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}▶${NC} $*"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC} $*"; }
fail()  { echo -e "${RED}✗${NC} $*"; exit 1; }
prompt() { local p="$1" def="${2:-}"; local r; if [ -n "$def" ]; then read -r -p "$p [$def]: " r; echo "${r:-$def}"; else read -r -p "$p: " r; echo "$r"; fi; }

# ── 인자 파싱 ───────────────────────────────────────────────────────
PROJECT_ID=""
PROJECT_NAME=""
ORG_ID=""
OWNER_EMAIL=""
REGION="asia-northeast3"
ALLOWED_EMAIL_DOMAINS=""
BILLING_ACCOUNT=""
SKIP_INTERACTIVE="${SKIP_INTERACTIVE:-0}"

while [ $# -gt 0 ]; do
  case "$1" in
    --project-id) PROJECT_ID="$2"; shift 2;;
    --project-name) PROJECT_NAME="$2"; shift 2;;
    --org-id) ORG_ID="$2"; shift 2;;
    --owner-email) OWNER_EMAIL="$2"; shift 2;;
    --region) REGION="$2"; shift 2;;
    --allowed-email-domains) ALLOWED_EMAIL_DOMAINS="$2"; shift 2;;
    --billing-account) BILLING_ACCOUNT="$2"; shift 2;;
    --yes|-y) SKIP_INTERACTIVE=1; shift;;
    -h|--help)
      sed -n '2,30p' "$0"; exit 0;;
    *) warn "알 수 없는 인자: $1"; shift;;
  esac
done

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  BoanClaw 관리자 설치 — GCP 조직 배포        ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ── 1. gcloud CLI 확인 ──────────────────────────────────────────────
info "[1/8] gcloud CLI 확인..."
if ! command -v gcloud >/dev/null 2>&1; then
  fail "gcloud CLI 가 설치되지 않았습니다.
  설치: https://cloud.google.com/sdk/docs/install
  (Mac: brew install --cask google-cloud-sdk)
  (Linux: curl -sSL https://sdk.cloud.google.com | bash)"
fi
ok "gcloud: $(gcloud --version | head -1)"

# terraform 도 확인
if ! command -v terraform >/dev/null 2>&1; then
  fail "terraform 이 설치되지 않았습니다.
  설치: https://developer.hashicorp.com/terraform/install
  (Mac: brew install terraform)"
fi
ok "terraform: $(terraform version | head -1)"

command -v openssl >/dev/null 2>&1 || fail "openssl 이 필요합니다."

# ── 2. gcloud auth ──────────────────────────────────────────────────
info "[2/8] GCP 계정 인증 확인..."
ACTIVE_ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null || true)"
if [ -z "$ACTIVE_ACCOUNT" ]; then
  warn "활성 gcloud 계정 없음 — 브라우저에서 로그인 진행합니다"
  gcloud auth login
  ACTIVE_ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null || true)"
  [ -n "$ACTIVE_ACCOUNT" ] || fail "gcloud 로그인 실패"
fi
ok "인증 계정: $ACTIVE_ACCOUNT"

# Application Default Credentials (terraform 이 사용)
if ! gcloud auth application-default print-access-token >/dev/null 2>&1; then
  warn "Application Default Credentials 없음 — 설정합니다"
  gcloud auth application-default login
fi
ok "ADC 설정 완료"

# ── 3. 인자 기본값 interactive 입력 ────────────────────────────────
if [ "$SKIP_INTERACTIVE" != "1" ]; then
  [ -n "$PROJECT_ID" ] || PROJECT_ID=$(prompt "GCP Project ID (예: sds-boanclaw-prod)")
  [ -n "$PROJECT_NAME" ] || PROJECT_NAME=$(prompt "Project 표시 이름" "$PROJECT_ID")
  [ -n "$ORG_ID" ] || ORG_ID=$(prompt "조직 식별자 (소문자+하이픈, 예: sds-corp)")
  [ -n "$OWNER_EMAIL" ] || OWNER_EMAIL=$(prompt "조직 소유자 이메일")
  [ -n "$REGION" ] || REGION=$(prompt "GCP Region" "asia-northeast3")
  [ -n "$ALLOWED_EMAIL_DOMAINS" ] || ALLOWED_EMAIL_DOMAINS=$(prompt "허용 이메일 도메인 (콤마 구분, 예: samsung.com,samsungsds.com)")
fi

for v in PROJECT_ID ORG_ID OWNER_EMAIL REGION ALLOWED_EMAIL_DOMAINS; do
  [ -n "${!v:-}" ] || fail "필수 값 누락: $v"
done

# ── 4. 프로젝트 존재 확인 / 생성 ────────────────────────────────────
info "[3/8] GCP 프로젝트 확인..."
if gcloud projects describe "$PROJECT_ID" >/dev/null 2>&1; then
  ok "기존 프로젝트 사용: $PROJECT_ID"
else
  warn "프로젝트 $PROJECT_ID 가 없습니다"
  if [ "$SKIP_INTERACTIVE" != "1" ]; then
    a=$(prompt "지금 생성할까요? (y/N)" "N")
    [[ "$a" =~ ^[Yy]$ ]] || fail "프로젝트가 없어 중단"
  fi
  info "프로젝트 생성 중: $PROJECT_ID"
  gcloud projects create "$PROJECT_ID" --name="$PROJECT_NAME" || fail "프로젝트 생성 실패 (프로젝트 ID 전역 고유해야 함)"
  ok "프로젝트 생성 완료"
fi
gcloud config set project "$PROJECT_ID" >/dev/null

# ── 5. 결제 계정 ────────────────────────────────────────────────────
info "[4/8] 결제 계정 연결 확인..."
CURRENT_BILLING="$(gcloud beta billing projects describe "$PROJECT_ID" --format='value(billingAccountName)' 2>/dev/null || true)"
if [ -z "$CURRENT_BILLING" ]; then
  warn "프로젝트에 결제 계정이 연결되어 있지 않습니다"
  # 사용 가능한 결제 계정 나열
  mapfile -t BILLING_ACCOUNTS < <(gcloud beta billing accounts list --filter=open=true --format='value(name)' 2>/dev/null || true)
  if [ "${#BILLING_ACCOUNTS[@]}" -eq 0 ]; then
    fail "활성 결제 계정 없음. https://console.cloud.google.com/billing 에서 먼저 결제 계정을 만들어주세요."
  fi
  if [ -z "$BILLING_ACCOUNT" ]; then
    if [ "${#BILLING_ACCOUNTS[@]}" -eq 1 ]; then
      BILLING_ACCOUNT="${BILLING_ACCOUNTS[0]}"
      ok "유일한 결제 계정 자동 선택: $BILLING_ACCOUNT"
    else
      echo "사용 가능한 결제 계정:"
      for i in "${!BILLING_ACCOUNTS[@]}"; do echo "  [$i] ${BILLING_ACCOUNTS[$i]}"; done
      idx=$(prompt "어느 것을 사용할까요? (번호)")
      BILLING_ACCOUNT="${BILLING_ACCOUNTS[$idx]}"
    fi
  fi
  gcloud beta billing projects link "$PROJECT_ID" --billing-account="$BILLING_ACCOUNT"
  ok "결제 계정 연결 완료: $BILLING_ACCOUNT"
else
  ok "결제 연결됨: $CURRENT_BILLING"
fi

# ── 6. API 활성화 ───────────────────────────────────────────────────
info "[5/8] 필수 API 활성화..."
APIS=(
  run.googleapis.com                        # Cloud Run
  compute.googleapis.com                    # VM workstations
  cloudbuild.googleapis.com                 # 이미지 빌드
  artifactregistry.googleapis.com           # 빌드 산출물
  containerregistry.googleapis.com          # gcr.io
  iam.googleapis.com                        # 서비스 계정
  secretmanager.googleapis.com              # credential vault
  iap.googleapis.com                        # workstation 접근 (선택)
  firebase.googleapis.com                   # 호스팅 (선택)
  firebasehosting.googleapis.com
)
for api in "${APIS[@]}"; do
  gcloud services enable "$api" --project="$PROJECT_ID" >/dev/null 2>&1 &
done
wait
ok "API ${#APIS[@]}개 활성화 완료"

# ── 7. IAM 권한 점검 ────────────────────────────────────────────────
info "[6/8] IAM 권한 점검..."
ROLES="$(gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten='bindings[].members' \
  --filter="bindings.members:user:$ACTIVE_ACCOUNT OR bindings.members:user:$ACTIVE_ACCOUNT" \
  --format='value(bindings.role)' 2>/dev/null | tr '\n' ' ' || true)"
if echo "$ROLES" | grep -qE 'roles/(owner|editor)'; then
  ok "$ACTIVE_ACCOUNT 가 Owner/Editor 권한 보유"
else
  warn "$ACTIVE_ACCOUNT 의 권한이 Owner/Editor 가 아닌 것 같습니다: $ROLES"
  warn "terraform apply 중 IAM 실패 가능. 필요 시 Project Owner 로 추가해주세요."
fi

# ── 8. Terraform 배포 (기존 스크립트 재활용) ───────────────────────
info "[7/8] Terraform + Cloud Run 배포..."
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$ROOT/deploy/config/gcp.env"
mkdir -p "$(dirname "$ENV_FILE")"
# gcp.env 에 이번 설치 값 기록 (이후 업데이트 시 재사용)
cat > "$ENV_FILE" <<EOF
BOAN_GCP_ORG_ID=$PROJECT_ID
PROJECT_ID=$PROJECT_ID
PROJECT_NAME=$PROJECT_NAME
REGION=$REGION
ORG_ID=$ORG_ID
BOAN_ORG_ID=$ORG_ID
BOAN_OWNER_EMAIL=$OWNER_EMAIL
BOAN_ALLOWED_EMAIL_DOMAINS=$ALLOWED_EMAIL_DOMAINS
BOAN_ALLOWED_SSO=email_otp
EOF
ok "gcp.env 작성: $ENV_FILE"

if [ ! -x "$ROOT/scripts/deploy_policy_server_gcp.sh" ]; then
  fail "scripts/deploy_policy_server_gcp.sh 실행 권한 없음 — chmod +x 후 재시도"
fi

info "terraform + Cloud Run 빌드/배포 시작 (10-20분 소요)..."
"$ROOT/scripts/deploy_policy_server_gcp.sh"

# ── 9. URL / TOKEN 출력 ─────────────────────────────────────────────
info "[8/8] 배포 결과 수집..."
POLICY_SERVICE_NAME="boan-policy-server-${ORG_ID}"
SERVICE_URL="$(gcloud run services describe "$POLICY_SERVICE_NAME" \
  --project="$PROJECT_ID" --region="$REGION" \
  --format='value(status.url)' 2>/dev/null || true)"
TOKEN_FILE="$ROOT/deploy/config/${ORG_ID}.token"
ORG_TOKEN=""
[ -f "$TOKEN_FILE" ] && ORG_TOKEN="$(cat "$TOKEN_FILE")"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  🎉 BoanClaw 조직 배포 완료!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  조직 ID:        ${CYAN}${ORG_ID}${NC}"
echo -e "  Project:        ${CYAN}${PROJECT_ID}${NC}"
echo -e "  소유자:         ${CYAN}${OWNER_EMAIL}${NC}"
echo -e "  Region:         ${CYAN}${REGION}${NC}"
echo -e "  Policy Server:  ${CYAN}${SERVICE_URL:-(조회 실패)}${NC}"
echo -e "  Org Token:      ${YELLOW}${ORG_TOKEN:-(조회 실패)}${NC}"
echo -e "    └ 위 token 은 $TOKEN_FILE 에 저장됨 (절대 공개 X)"
echo ""
echo -e "${CYAN}── 사용자 한 줄 설치 명령 ──${NC}"
cat <<USAGEEOF
다음을 조직원(사용자)에게 전달하세요:

  curl -fsSL https://<boanclaw-host>/install.sh | \\
    BOAN_ORG_URL=${SERVICE_URL} \\
    BOAN_ORG_TOKEN=${ORG_TOKEN} \\
    BOAN_ORG_ID=${ORG_ID} \\
    bash

(<boanclaw-host> 는 BoanClaw 소스를 호스팅하는 곳. 또는 사용자가 이미
소스를 가지고 있다면 cd BoanClaw && ./install.sh 로도 동일.)

사용자가 install.sh 를 실행하면:
  • 로컬에 Docker 컨테이너 시작
  • 첫 로그인 시 조직 서버에 "가입 요청" 상태로 등록
  • 관리자(소유자)가 Admin Console 의 Authorization 탭에서 승인
  • 승인되면 VM 이 자동 할당되어 Personal Computer 사용 가능
USAGEEOF
echo ""
