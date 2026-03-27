FROM golang:1.21-alpine AS onecli-builder
WORKDIR /src
COPY boan-onecli/go.mod .
RUN go mod download
COPY boan-onecli/ .
RUN CGO_ENABLED=0 GOOS=linux go build -o /boan-onecli .

FROM node:22-slim AS base
RUN apt-get update && \
    apt-get install -y --no-install-recommends git ca-certificates curl && \
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
COPY --from=plugin-build /build/dist /opt/boanclaw/dist
COPY --from=plugin-build /build/node_modules /opt/boanclaw/node_modules
COPY --from=plugin-build /build/package.json /opt/boanclaw/package.json
COPY --from=plugin-build /build/src/plugin.json /opt/boanclaw/plugin.json

COPY boan-sandbox/git-guard.sh /usr/local/bin/git-guard
RUN chmod +x /usr/local/bin/git-guard /usr/local/bin/boan-onecli && \
    mv /usr/bin/git /usr/bin/git-real && \
    ln -s /usr/local/bin/git-guard /usr/local/bin/git

COPY boan-sandbox/entrypoint.sh /entrypoint.sh
COPY boan-sandbox/mount-check.sh /mount-check.sh
RUN chmod +x /entrypoint.sh /mount-check.sh

RUN groupadd -g 1000 boan && \
    useradd -u 1000 -g boan -m -s /bin/sh boan

RUN mkdir -p /workspace /tmp/boan && \
    chown -R boan:boan /workspace /tmp/boan /opt/boanclaw

WORKDIR /workspace

ENV HTTP_PROXY=http://boan-proxy:18080
ENV HTTPS_PROXY=http://boan-proxy:18080
ENV BOAN_PROXY_ADMIN=http://boan-proxy:18081
ENV ANTHROPIC_BASE_URL=http://localhost:8083
ENV BOAN_ONECLI_LISTEN=:8083
ENV BOAN_ONECLI_CRED_FILTER_URL=http://boan-credential-filter:8082
ENV BOAN_ONECLI_ORG_ID=default
ENV BOAN_ONECLI_UPSTREAM_URL=https://api.anthropic.com
ENV BOAN_ONECLI_CREDENTIAL_NAME=anthropic_api_key
ENV BOAN_ONECLI_CREDENTIAL_TYPE=api_key
ENV BOAN_ONECLI_RATE_LIMIT_RPM=60
ENV NODE_ENV=production

EXPOSE 18789

USER boan

ENTRYPOINT ["/entrypoint.sh"]
