#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# build-installer.sh — BoanClaw 한 줄 설치 패키지 생성
#
# 사용:
#   ./scripts/build-installer.sh <BASE_URL>
#
#   <BASE_URL> 은 install.sh 와 boanclaw-<version>.tar.gz 가 함께 올라갈
#   웹 호스팅 prefix. 예:
#     https://github.com/arizona95/SDS-RED/releases/download/v2026.4.10
#     https://example.com/boanclaw
#     http://localhost:8000   (로컬 테스트용)
#
# 출력 (dist/ 안):
#   install.sh                  — 작은 shim (~3KB), curl|bash 으로 직접 실행 가능
#   boanclaw-<version>.tar.gz   — 실제 소스 (~2MB)
#
# 두 파일을 같은 BASE_URL 아래 올리면 누구든 다음 한 줄로 설치:
#
#   curl -fsSL <BASE_URL>/install.sh | bash
#
# 로컬 테스트:
#   ./scripts/build-installer.sh http://localhost:8000
#   (cd dist && python3 -m http.server 8000) &
#   curl -fsSL http://localhost:8000/install.sh | bash
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASE_URL="${1:-}"
if [ -z "$BASE_URL" ]; then
  echo "Usage: $0 <BASE_URL>"
  echo "  e.g.  $0 http://localhost:8000"
  echo "        $0 https://github.com/arizona95/SDS-RED/releases/download/v2026.4.10"
  exit 1
fi
BASE_URL="${BASE_URL%/}"

VERSION="$(grep -E '^ARG OPENCLAW_VERSION=' src/packages/boan-sandbox/Dockerfile | head -1 | cut -d= -f2)"
[ -n "$VERSION" ] || VERSION="dev-$(date +%Y%m%d)"

DIST_DIR="$ROOT/dist"
TARBALL_NAME="boanclaw-${VERSION}.tar.gz"
TARBALL="$DIST_DIR/$TARBALL_NAME"
SHIM="$DIST_DIR/install.sh"

echo "▶ Packaging BoanClaw installer"
echo "  version:  $VERSION"
echo "  base url: $BASE_URL"
echo "  tarball:  $TARBALL_NAME"
echo

mkdir -p "$DIST_DIR"
rm -f "$TARBALL" "$SHIM"

# ── 1. 소스 tarball ───────────────────────────────────────────────────
# 제외 대상:
#   - node_modules (npm install 산출물)
#   - .git (어디에 있든)
#   - dist/ (빌드 산출물)
#   - terraform providers / state (수백 MB, 사용자가 별도 init)
#   - test 대용량 데이터, 무거운 image / lock 파일
#   - vendored open-computer-use (상위 SDS-RED 가 별도 관리)
echo "▶ Creating source tarball (excluding node_modules / terraform / dist / .git / vendored repos)..."
tar \
  --exclude='*/node_modules' \
  --exclude='./node_modules' \
  --exclude='*/.git' \
  --exclude='./.git' \
  --exclude='*/dist' \
  --exclude='./dist' \
  --exclude='./deploy/terraform' \
  --exclude='*/.terraform' \
  --exclude='*.tfstate' \
  --exclude='*.tfstate.backup' \
  --exclude='./test/data' \
  --exclude='./ai-security-test*.json' \
  --exclude='./boanclaw_v4.html' \
  --exclude='./src/open-computer-use' \
  -czf "$TARBALL" . 2>/dev/null

TAR_SIZE=$(du -h "$TARBALL" | awk '{print $1}')
TAR_SHA=$(sha256sum "$TARBALL" | awk '{print $1}')
echo "  size:   $TAR_SIZE"
echo "  sha256: $TAR_SHA"

# ── 2. install.sh shim ────────────────────────────────────────────────
# embed: BASE_URL, tarball name, sha256.
# shim 은 자기 파일을 안 읽고 단순히 curl 로 tarball 받아서 풀고 그 안의
# install.sh 를 실행함 → curl|bash 와 100% 호환.
echo "▶ Generating install.sh shim..."
cat > "$SHIM" <<INSTALL_SHIM
#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# BoanClaw 한 줄 설치 — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# version: ${VERSION}
#
# 사용:
#   curl -fsSL ${BASE_URL}/install.sh | bash
#
# 또는 환경 변수 override:
#   BOANCLAW_INSTALL_DIR=/opt/boanclaw curl -fsSL ${BASE_URL}/install.sh | bash
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

# 빌드 시점에 박힌 값들
BOANCLAW_VERSION="${VERSION}"
BOANCLAW_TARBALL_URL="${BASE_URL}/${TARBALL_NAME}"
BOANCLAW_TARBALL_SHA256="${TAR_SHA}"
INSTALL_DIR="\${BOANCLAW_INSTALL_DIR:-\$HOME/boanclaw}"

# ── 색상 ──
if [ -t 1 ]; then
  R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; C='\033[0;36m'; N='\033[0m'
else R=; G=; Y=; C=; N=; fi
info() { printf "\${C}▶\${N} %s\n" "\$*"; }
ok()   { printf "  \${G}✓\${N} %s\n" "\$*"; }
fail() { printf "\${R}✗\${N} %s\n" "\$*"; exit 1; }

echo
printf "\${C}╔══════════════════════════════════════╗\${N}\n"
printf "\${C}║         BoanClaw Installer           ║\${N}\n"
printf "\${C}║         version: %-22s║\${N}\n" "\$BOANCLAW_VERSION"
printf "\${C}╚══════════════════════════════════════╝\${N}\n"
echo

# ── 1. 필수 도구 ──────────────────────────────────────────────────────
need() { command -v "\$1" >/dev/null 2>&1 || fail "'\$1' 이 설치되어 있지 않습니다"; }
info "필수 도구 확인..."
need curl
need tar
need sha256sum
need docker
if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then COMPOSE="docker-compose"
else fail "docker compose plugin 이 없습니다"; fi
docker info >/dev/null 2>&1 || fail "Docker 데몬이 실행 중이 아닙니다 (sudo systemctl start docker)"
ok "curl / tar / docker / \$COMPOSE OK"

# ── 2. 소스 tarball 다운로드 + 검증 ────────────────────────────────────
TMP="\$(mktemp -d -t boanclaw-install.XXXXXX)"
trap 'rm -rf "\$TMP"' EXIT
TARBALL="\$TMP/${TARBALL_NAME}"

info "소스 tarball 다운로드: \$BOANCLAW_TARBALL_URL"
curl -fsSL "\$BOANCLAW_TARBALL_URL" -o "\$TARBALL" || fail "download failed"
ok "다운로드 완료 (\$(du -h \$TARBALL | awk '{print \$1}'))"

info "sha256 무결성 검증..."
ACTUAL=\$(sha256sum "\$TARBALL" | awk '{print \$1}')
if [ "\$ACTUAL" != "\$BOANCLAW_TARBALL_SHA256" ]; then
  fail "sha256 mismatch
  expected: \$BOANCLAW_TARBALL_SHA256
  actual:   \$ACTUAL"
fi
ok "sha256 일치"

# ── 3. \$INSTALL_DIR 에 풀기 ────────────────────────────────────────────
info "소스 추출: \$INSTALL_DIR"
mkdir -p "\$INSTALL_DIR"
tar -xzf "\$TARBALL" -C "\$INSTALL_DIR"
[ -f "\$INSTALL_DIR/install.sh" ] || fail "install.sh not found after extract"
ok "추출 완료"

# ── 4. 추출된 install.sh 실행 ─────────────────────────────────────────
chmod +x "\$INSTALL_DIR/install.sh"
exec "\$INSTALL_DIR/install.sh"
INSTALL_SHIM

chmod +x "$SHIM"

echo
echo "═══════════════════════════════════════════════════"
echo "  ✓ Installer built successfully"
echo "═══════════════════════════════════════════════════"
echo "  Files in $DIST_DIR/ :"
ls -lh "$DIST_DIR" | awk 'NR>1 {printf "    %s  %s\n", $5, $NF}'
echo
echo "  배포 절차:"
echo "    1. dist/install.sh + dist/$TARBALL_NAME 두 파일을"
echo "       같은 prefix 아래 (= $BASE_URL) 호스팅."
echo
echo "       예시 — 로컬 테스트:"
echo "         (cd $DIST_DIR && python3 -m http.server 8000)"
echo
echo "       예시 — GitHub release:"
echo "         gh release create v$VERSION $SHIM $TARBALL"
echo
echo "    2. 사용자는 한 줄로 설치:"
echo
echo "         curl -fsSL $BASE_URL/install.sh | bash"
echo
