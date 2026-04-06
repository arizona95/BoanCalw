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
    apt-get install -y --no-install-recommends git ca-certificates curl gosu && \
    rm -rf /var/lib/apt/lists/*
RUN npm install -g openclaw@latest

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

RUN groupadd -g 2000 boan && \
    useradd -u 2000 -g 2000 -m -s /bin/sh boan

RUN mkdir -p /workspace /tmp/boan /data/users /data/registry /data/credentials /etc/boan-cred && \
    chown -R boan:boan /workspace /tmp/boan /opt/boanclaw /data /etc/boan-cred

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
