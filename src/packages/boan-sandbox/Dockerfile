FROM golang:1.21-alpine AS onecli-builder
WORKDIR /src
COPY boan-onecli/go.mod ./
COPY boan-onecli/ .
RUN go mod download 2>/dev/null || true
RUN CGO_ENABLED=0 GOOS=linux go build -o /boan-onecli .

FROM golang:1.25-alpine AS proxy-builder
WORKDIR /app
COPY boan-proxy/go.mod boan-proxy/go.sum ./
RUN go mod download
COPY boan-proxy/ .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /boan-proxy ./cmd/proxy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /boan-audit ./cmd/audit

FROM golang:1.23-alpine AS cred-builder
WORKDIR /app
COPY boan-credential-filter/go.mod ./
COPY boan-credential-filter/ .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /boan-credential-filter .

FROM golang:1.23-alpine AS registry-builder
WORKDIR /app
COPY boan-llm-registry/go.mod ./
COPY boan-llm-registry/ .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /boan-llm-registry .

FROM golang:1.23-alpine AS whitelist-builder
WORKDIR /app
COPY boan-whitelist-proxy/go.mod ./
COPY boan-whitelist-proxy/ .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /boan-whitelist-proxy .

FROM node:22-slim AS base
RUN apt-get update && \
    apt-get install -y --no-install-recommends git ca-certificates curl gosu \
                                              openssh-client sshpass coreutils && \
    rm -rf /var/lib/apt/lists/*

# OpenClaw 는 외부 npm 패키지라 supply-chain 공격 대상이다. `@latest` 는
# `npm publish` 가 일어날 때마다 무성으로 바뀌므로 절대 사용 금지.
# 빌드 시점에 (a) 명시적 버전을 핀하고 (b) 설치된 openclaw.mjs 의 sha256 을
# /opt/boanclaw-meta 에 기록한다. entrypoint 가 시작 직전에 같은 두 값을
# 다시 계산해서 일치 여부를 검사하고, 불일치면 fail-closed 로 종료한다.
# 새 OpenClaw 를 허용하려면: OPENCLAW_VERSION 을 올리고 rebuild → 새 hash 로 갱신.
ARG OPENCLAW_VERSION=2026.4.9
RUN npm install -g openclaw@${OPENCLAW_VERSION} && \
    OPENCLAW_DIR="$(npm config get prefix)/lib/node_modules/openclaw" && \
    INSTALLED_VERSION="$(node -e "console.log(require('${OPENCLAW_DIR}/package.json').version)")" && \
    if [ "${INSTALLED_VERSION}" != "${OPENCLAW_VERSION}" ]; then \
        echo "OpenClaw version mismatch at build: expected=${OPENCLAW_VERSION} installed=${INSTALLED_VERSION}" >&2; \
        exit 1; \
    fi && \
    mkdir -p /opt/boanclaw-meta && \
    sha256sum "${OPENCLAW_DIR}/openclaw.mjs" | awk '{print $1}' > /opt/boanclaw-meta/openclaw.mjs.sha256 && \
    echo "${OPENCLAW_VERSION}" > /opt/boanclaw-meta/openclaw.version && \
    echo "[boan-sandbox build] OpenClaw pinned: ${OPENCLAW_VERSION} sha256=$(cat /opt/boanclaw-meta/openclaw.mjs.sha256)"

FROM base AS plugin-build
WORKDIR /build
COPY boan-agent/package.json boan-agent/tsconfig.json ./
RUN npm install
COPY boan-agent/src/ src/
RUN npm run build

FROM base

COPY --from=onecli-builder /boan-onecli /usr/local/bin/boan-onecli
COPY --from=proxy-builder /boan-proxy /boan-audit /usr/local/bin/
COPY --from=cred-builder /boan-credential-filter /usr/local/bin/
COPY --from=registry-builder /boan-llm-registry /usr/local/bin/
COPY --from=whitelist-builder /boan-whitelist-proxy /usr/local/bin/
COPY --from=plugin-build /build/dist /opt/boanclaw/dist
COPY --from=plugin-build /build/node_modules /opt/boanclaw/node_modules
COPY --from=plugin-build /build/package.json /opt/boanclaw/package.json
COPY --from=plugin-build /build/src/plugin.json /opt/boanclaw/plugin.json
COPY --from=plugin-build /build/src/plugin.json /opt/boanclaw/openclaw.plugin.json

COPY boan-sandbox/git-guard.sh /usr/local/bin/git-guard
RUN chmod +x /usr/local/bin/git-guard /usr/local/bin/boan-onecli && \
    mv /usr/bin/git /usr/bin/git-real && \
    ln -s /usr/local/bin/git-guard /usr/local/bin/git

COPY boan-sandbox/entrypoint.sh /entrypoint.sh
COPY boan-sandbox/mount-check.sh /mount-check.sh
RUN chmod +x /entrypoint.sh /mount-check.sh

# boan UID/GID 는 빌드 시 host 사용자와 일치시키기 위해 ARG 로 노출.
# host bind mount(예: ~/Desktop/boanclaw)에 sandbox 가 쓰는 파일이
# host 에서 본인 소유로 보이게 하려면 boan UID = host user UID 여야 한다.
# 기본값 1000 은 일반 Linux 데스크탑 첫 사용자 UID. compose 에서
# `BOAN_UID=$(id -u) BOAN_GID=$(id -g)` 로 override 가능.
# (k8s prod 매니페스트는 host bind mount 가 없어서 별도로 2000 고정 유지)
ARG BOAN_UID=1000
ARG BOAN_GID=1000
# node:22-slim 베이스에는 이미 uid/gid 1000 = `node` 가 있어서 같은 슬롯을
# 그냥 useradd 하면 충돌한다. 점유된 슬롯이면 기존 user/group 을 먼저 제거한
# 뒤 boan 을 새로 만든다. (build-time root 권한이라 안전)
RUN if existing_user="$(getent passwd ${BOAN_UID} | cut -d: -f1)" && [ -n "$existing_user" ]; then \
        userdel -r "$existing_user" 2>/dev/null || userdel "$existing_user"; \
    fi && \
    if existing_group="$(getent group ${BOAN_GID} | cut -d: -f1)" && [ -n "$existing_group" ]; then \
        groupdel "$existing_group" 2>/dev/null || true; \
    fi && \
    groupadd -g ${BOAN_GID} boan && \
    useradd -u ${BOAN_UID} -g ${BOAN_GID} -m -s /bin/sh boan

RUN mkdir -p /workspace /tmp/boan /data/users /data/registry /data/credentials && \
    chown -R boan:boan /workspace /tmp/boan /opt/boanclaw /data

WORKDIR /workspace

ENV HTTP_PROXY=http://localhost:18080
ENV HTTPS_PROXY=http://localhost:18080
ENV BOAN_PROXY_ADMIN=http://localhost:18081
ENV ANTHROPIC_BASE_URL=http://localhost:8083
ENV BOAN_ONECLI_LISTEN=:8083
ENV BOAN_ONECLI_CRED_FILTER_URL=http://localhost:8082
ENV BOAN_ONECLI_ORG_ID=default
ENV BOAN_ONECLI_UPSTREAM_URL=https://api.anthropic.com
ENV BOAN_ONECLI_CREDENTIAL_NAME=anthropic_api_key
ENV BOAN_ONECLI_CREDENTIAL_TYPE=api_key
ENV BOAN_ONECLI_RATE_LIMIT_RPM=60
ENV NODE_ENV=production

EXPOSE 18080 18081 8082 8085 8086 18789

ENTRYPOINT ["/entrypoint.sh"]
