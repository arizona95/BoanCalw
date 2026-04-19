#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# BoanClaw — 설치 스크립트
#
# 두 가지 실행 방식 모두 지원:
#
#   (A) 이미 BoanClaw 소스를 받은 상태 (가장 흔함):
#       cd /path/to/BoanClaw
#       ./install.sh
#       → 스크립트 옆에 docker-compose.dev.yml 이 있으면 그 디렉토리를 그대로
#         사용하고 git clone 안 함.
#
#   (B) curl 한 줄 (소스 호스팅 후):
#       curl -fsSL https://<your-host>/install.sh | bash
#       → BOANCLAW_REPO_URL 의 git 저장소를 BOANCLAW_INSTALL_DIR 로 clone 한 뒤
#         그 안에서 (A) 와 동일한 절차 실행.
#
# 환경 변수 (선택):
#   BOANCLAW_REPO_URL    git clone 모드일 때 사용할 저장소 URL
#                        (default: 비어있음 → clone 안 하고 (A) 모드 강제)
#   BOANCLAW_INSTALL_DIR clone 받을 위치       (default: $HOME/boanclaw)
#   BOAN_UID / BOAN_GID  sandbox 컨테이너 사용자 UID/GID (default: 호스트 사용자)
#
# 하는 일 (어느 모드든 동일):
#   1. 필수 도구 확인 (docker, docker compose, git, curl)
#   2. Docker 데몬 동작 확인
#   3. 소스 위치 결정: 스크립트 옆 / 기존 클론 / 새 클론
#   4. $HOME/Desktop/boanclaw 폴더 생성 (S3↔S2 마운트 경로)
#   5. 호스트 UID/GID 자동 감지 + sandbox 빌드 args 로 전달
#   6. Docker 이미지 빌드 + 컨테이너 시작 (scripts/rebuild.sh)
#   7. OpenClaw 무결성 검증 (sandbox entrypoint 가 자동 검사 — 실패 시 시작 안 됨)
#   8. 관리 콘솔 헬스 체크 후 안내 출력
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

# ── 색상 ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}▶${NC} $*"; }
ok()    { echo -e "${GREEN}✓${NC} $*"; }
warn()  { echo -e "${YELLOW}⚠${NC} $*"; }
fail()  { echo -e "${RED}✗${NC} $*"; exit 1; }

# ── 설정 ──
REPO_URL="${BOANCLAW_REPO_URL:-}"                       # 비어있으면 clone 안 함
INSTALL_DIR="${BOANCLAW_INSTALL_DIR:-$HOME/boanclaw}"
COMPOSE_FILE="docker-compose.dev.yml"
MOUNT_DIR="$HOME/Desktop/boanclaw"
ADMIN_PORT=19080

# 스크립트 자기 디렉토리 — 여기 옆에 docker-compose.dev.yml 이 있으면 그 위치 사용.
# (curl|bash 로 받은 경우는 BASH_SOURCE 가 /dev/fd/63 등이라 dirname 이 정상값 아님 →
# 그때는 자동으로 (B) clone 모드로 떨어짐.)
SCRIPT_DIR=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

echo ""
echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
echo -e "${CYAN}║         BoanClaw Installer           ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
echo ""

# ── 1. 필수 도구 확인 ──
info "필수 도구 확인..."

command -v git    &>/dev/null || fail "git 이 설치되어 있지 않습니다. 먼저 설치해주세요."
command -v curl   &>/dev/null || fail "curl 이 설치되어 있지 않습니다."
command -v docker &>/dev/null || fail "docker 가 설치되어 있지 않습니다. https://docs.docker.com/get-docker/"

if docker compose version &>/dev/null 2>&1; then
  COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
  COMPOSE="docker-compose"
else
  fail "docker compose 플러그인이 없습니다. Docker Desktop 또는 compose plugin 을 설치해주세요."
fi

# docker 데몬 실행 확인
docker info &>/dev/null || fail "Docker 데몬이 실행 중이 아닙니다. Docker 를 시작해주세요."

ok "git, docker, $COMPOSE 확인 완료"

# ── 2. 소스 위치 결정 ──
# 우선순위:
#   (a) 스크립트 옆에 docker-compose.dev.yml 이 있으면 그 디렉토리 (가장 흔함)
#   (b) BOANCLAW_INSTALL_DIR 가 이미 git checkout 이면 거기서 git pull
#   (c) BOANCLAW_REPO_URL 이 설정돼 있으면 거기서 git clone
#   (d) 셋 다 안 되면 명확한 에러 + 안내
if [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/$COMPOSE_FILE" ]; then
  INSTALL_DIR="$SCRIPT_DIR"
  ok "기존 BoanClaw 체크아웃 발견: $INSTALL_DIR (clone 안 함)"
elif [ -d "$INSTALL_DIR/.git" ]; then
  info "기존 설치 감지: $INSTALL_DIR — 최신 소스로 업데이트..."
  cd "$INSTALL_DIR"
  git pull --ff-only 2>/dev/null || warn "git pull 실패 (로컬 변경 있으면 무시)"
  ok "소스 업데이트 완료"
elif [ -n "$REPO_URL" ]; then
  info "BoanClaw 소스 다운로드 → $INSTALL_DIR ..."
  git clone "$REPO_URL" "$INSTALL_DIR"
  ok "소스 다운로드 완료"
else
  echo
  fail "BoanClaw 소스를 찾을 수 없습니다.
   - 이미 소스가 있다면: cd <BoanClaw 디렉토리> && ./install.sh
   - git 으로 받으려면: BOANCLAW_REPO_URL=<repo url> $0
   - 압축으로 받으려면: 압축 풀고 그 안에서 ./install.sh"
fi

cd "$INSTALL_DIR"
[ -f "$COMPOSE_FILE" ] || fail "$COMPOSE_FILE 가 $INSTALL_DIR 에 없습니다 — 잘못된 디렉토리?"

# ── 3. 바탕화면/boanclaw 폴더 생성 ──
info "S3 마운트 폴더 생성: $MOUNT_DIR"
mkdir -p "$MOUNT_DIR"
ok "$MOUNT_DIR 생성 완료"

# ── 4. 환경 설정 (최초 설치 시) ──
# 사용자가 관리자로부터 받은 조직 URL + Token 을 환경변수로 전달하면
# 로컬 proxy 가 해당 조직에 가입 요청을 보내도록 설정한다.
# 한 줄 설치 예:
#   curl ... | BOAN_ORG_URL=https://... BOAN_ORG_TOKEN=xxx BOAN_ORG_ID=sds-corp bash
ENV_FILE="deploy/config/gcp.env"
if [ -n "${BOAN_ORG_URL:-}" ] && [ -n "${BOAN_ORG_TOKEN:-}" ] && [ -n "${BOAN_ORG_ID:-}" ]; then
  info "조직 서버 연결 설정 (관리자 제공 값 사용)"
  mkdir -p "$(dirname "$ENV_FILE")"
  cat > "$ENV_FILE" <<ENVEOF
# 관리자(admin-install.sh)가 배포한 조직에 연결하기 위한 값.
BOAN_ORG_ID=$BOAN_ORG_ID
BOAN_POLICY_URL=$BOAN_ORG_URL
BOAN_ORG_TOKEN=$BOAN_ORG_TOKEN
ENVEOF
  # token 파일에도 쓰기 — 일관성
  mkdir -p "deploy/config"
  printf '%s' "$BOAN_ORG_TOKEN" > "deploy/config/${BOAN_ORG_ID}.token"
  chmod 600 "deploy/config/${BOAN_ORG_ID}.token" 2>/dev/null || true
  ok "조직 연결: $BOAN_ORG_ID → $BOAN_ORG_URL"
elif [ ! -f "$ENV_FILE" ]; then
  info "기본 환경 파일 생성: $ENV_FILE"
  mkdir -p "$(dirname "$ENV_FILE")"
  cat > "$ENV_FILE" <<'ENVEOF'
# 조직 연결 (관리자가 admin-install.sh 실행 후 받은 값을 넣으세요):
# BOAN_ORG_ID=
# BOAN_POLICY_URL=
# BOAN_ORG_TOKEN=
ENVEOF
  warn "BOAN_ORG_URL / BOAN_ORG_TOKEN / BOAN_ORG_ID 미지정 — 단독 모드로 실행됩니다"
  warn "조직에 가입하려면 관리자로부터 URL/Token 을 받아 $ENV_FILE 에 채우거나"
  warn "환경변수로 다시 실행: BOAN_ORG_URL=... BOAN_ORG_TOKEN=... BOAN_ORG_ID=... ./install.sh"
fi

# ── 5. 호스트 UID/GID 자동 감지 ──
# sandbox 컨테이너가 호스트 사용자와 같은 UID/GID 로 동작하면 host bind mount
# (~/Desktop/boanclaw) 에 만들어진 파일이 호스트에서 본인 소유로 보인다.
# (sudo 없이 편집 가능) — 이 두 변수는 docker-compose build args 로 전달.
export BOAN_UID="${BOAN_UID:-$(id -u)}"
export BOAN_GID="${BOAN_GID:-$(id -g)}"
ok "sandbox 사용자 UID:GID = ${BOAN_UID}:${BOAN_GID} (호스트와 일치)"

# ── 5.5. 버전 파일 생성 + 업데이트 워처 ──
if command -v git &>/dev/null && [ -d "$INSTALL_DIR/.git" ]; then
  git -C "$INSTALL_DIR" rev-parse --short HEAD > "$INSTALL_DIR/.boanclaw-version" 2>/dev/null || true
  ok "버전: $(cat "$INSTALL_DIR/.boanclaw-version" 2>/dev/null || echo 'unknown')"
fi

# 업데이트 트리거 디렉토리 (container 에서 접근 가능해야 함)
mkdir -p /tmp/boanclaw-triggers
rm -f /tmp/boanclaw-triggers/update-requested

# 업데이트 워처 (기존 인스턴스 종료 후 재시작)
pkill -f "update-watcher.sh" 2>/dev/null || true
if [ -x "$INSTALL_DIR/scripts/update-watcher.sh" ]; then
  nohup bash "$INSTALL_DIR/scripts/update-watcher.sh" "$INSTALL_DIR" > /dev/null 2>&1 &
  ok "업데이트 워처 시작 (PID: $!)"
fi

# ── 6. Docker 이미지 빌드 + 컨테이너 시작 ──
info "Docker 이미지 빌드 중... (최초 실행 시 5-10분 소요)"
info "  └ OpenClaw 는 빌드 시점에 핀된 버전 + sha256 으로 무결성 검증됩니다"

# rebuild.sh 가 있으면 (proxy/sandbox/console 동시 빌드 보장 — 메모리에 기록된 운영 규칙)
# 사용, 없으면 일반 compose build/up 으로 fallback.
if [ -x ./scripts/rebuild.sh ]; then
  ./scripts/rebuild.sh 2>&1 | tail -8
else
  $COMPOSE -f "$COMPOSE_FILE" build 2>&1 | tail -5
  info "컨테이너 시작..."
  $COMPOSE -f "$COMPOSE_FILE" up -d 2>&1 | tail -10
fi

# OpenClaw 무결성 검증은 sandbox entrypoint 에서 자동 수행. 실패 시 sandbox
# 컨테이너가 즉시 종료되므로 healthcheck 가 자연스럽게 실패한다. 별도 호출 불필요.

# ── 7. 헬스 체크 ──
info "서비스 상태 확인 중..."
MAX_WAIT=120
ELAPSED=0
while [ $ELAPSED -lt $MAX_WAIT ]; do
  if curl -sf "http://localhost:$ADMIN_PORT/" > /dev/null 2>&1; then
    break
  fi
  sleep 2
  ELAPSED=$((ELAPSED + 2))
  printf "\r  %ds / %ds..." "$ELAPSED" "$MAX_WAIT"
done
echo ""

if curl -sf "http://localhost:$ADMIN_PORT/" > /dev/null 2>&1; then
  echo ""
  echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
  echo -e "${GREEN}  BoanClaw 설치 완료!${NC}"
  echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
  echo ""
  echo -e "  관리 콘솔:    ${CYAN}http://localhost:$ADMIN_PORT${NC}"
  echo -e "  마운트 폴더:  ${CYAN}$MOUNT_DIR${NC}"
  echo -e "  설치 경로:    $INSTALL_DIR"
  if [ -n "${BOAN_ORG_URL:-}" ]; then
    echo -e "  조직:         ${CYAN}${BOAN_ORG_ID}${NC} @ ${CYAN}${BOAN_ORG_URL}${NC}"
  fi
  echo ""
  if [ -n "${BOAN_ORG_URL:-}" ]; then
    echo -e "${YELLOW}다음 단계 (사용자):${NC}"
    echo -e "  1. 브라우저에서 ${CYAN}http://localhost:$ADMIN_PORT${NC} 접속"
    echo -e "  2. 회사 이메일로 로그인 → 조직 서버에 '가입 요청' 상태로 등록됨"
    echo -e "  3. 관리자가 Authorization 탭에서 승인하면 VM 이 자동 할당됨"
    echo -e "  4. Personal Computer 탭에서 원격 Windows 사용 가능"
  fi
  echo ""
  echo -e "  시작:  ${YELLOW}cd $INSTALL_DIR && $COMPOSE -f $COMPOSE_FILE up -d${NC}"
  echo -e "  중지:  ${YELLOW}cd $INSTALL_DIR && $COMPOSE -f $COMPOSE_FILE down${NC}"
  echo -e "  재빌드: ${YELLOW}cd $INSTALL_DIR && ./scripts/rebuild.sh${NC}"
  echo ""
else
  warn "서비스가 아직 준비되지 않았습니다 (${MAX_WAIT}초 대기 후 타임아웃)."
  warn "수동 확인: cd $INSTALL_DIR && $COMPOSE -f $COMPOSE_FILE ps"
fi
