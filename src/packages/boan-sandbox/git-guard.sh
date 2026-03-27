#!/bin/sh

REAL_GIT="/usr/bin/git-real"
AUDIT_LOG="/tmp/boan-audit.log"
SESSION_ID="${BOAN_SESSION_ID:-default}"
BRANCH="boanclaw/${SESSION_ID}"

log_blocked() {
  echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"event\":\"git_blocked\",\"command\":\"git $*\",\"session\":\"${SESSION_ID}\"}" >> "${AUDIT_LOG}"
  echo "[boan-git-guard] BLOCKED: git $*"
  echo "[boan-git-guard] This command is restricted by BoanClaw security policy."
  exit 1
}

check_blocked() {
  case "$1" in
    reset)
      shift
      for arg in "$@"; do
        if [ "$arg" = "--hard" ]; then
          log_blocked reset --hard "$@"
        fi
      done
      ;;
    push)
      shift
      for arg in "$@"; do
        case "$arg" in
          --force|--force-with-lease|-f)
            log_blocked push "$arg" "$@"
            ;;
        esac
      done
      ;;
    rebase)
      shift
      for arg in "$@"; do
        case "$arg" in
          -i|--interactive)
            log_blocked rebase "$arg" "$@"
            ;;
        esac
      done
      ;;
    commit)
      shift
      for arg in "$@"; do
        if [ "$arg" = "--amend" ]; then
          log_blocked commit --amend "$@"
        fi
      done
      ;;
    clean)
      shift
      for arg in "$@"; do
        case "$arg" in
          -fd|-f)
            log_blocked clean "$arg" "$@"
            ;;
        esac
      done
      ;;
    checkout)
      if [ "$2" = "--" ] && [ "$3" = "." ]; then
        log_blocked checkout -- .
      fi
      ;;
    rm)
      if [ "$2" = "-rf" ] && [ "$3" = ".git" ]; then
        log_blocked rm -rf .git
      fi
      ;;
  esac
}

auto_commit() {
  CURRENT=$("${REAL_GIT}" branch --show-current 2>/dev/null || echo "")
  if [ "${CURRENT}" != "${BRANCH}" ]; then
    "${REAL_GIT}" checkout -b "${BRANCH}" 2>/dev/null || "${REAL_GIT}" checkout "${BRANCH}" 2>/dev/null || return 0
  fi

  CHANGES=$("${REAL_GIT}" status --porcelain 2>/dev/null)
  if [ -n "${CHANGES}" ]; then
    "${REAL_GIT}" add -A 2>/dev/null
    "${REAL_GIT}" commit -m "[boanclaw] auto-commit (session: ${SESSION_ID})" --allow-empty 2>/dev/null || true
    echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"event\":\"auto_commit\",\"branch\":\"${BRANCH}\",\"session\":\"${SESSION_ID}\"}" >> "${AUDIT_LOG}"
  fi

  if [ -n "${CURRENT}" ] && [ "${CURRENT}" != "${BRANCH}" ]; then
    "${REAL_GIT}" checkout "${CURRENT}" 2>/dev/null || true
  fi
}

check_blocked "$@"

"${REAL_GIT}" "$@"
EXIT_CODE=$?

case "$1" in
  add|commit|merge|cherry-pick|revert|apply|am)
    auto_commit
    ;;
esac

exit ${EXIT_CODE}
