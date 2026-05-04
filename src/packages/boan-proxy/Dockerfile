FROM golang:1.25-alpine AS builder
# BOAN_BUILD_TAG 는 "testmode" 또는 "release". 기본 release — test 엔드포인트 /
# OTP 우회 / Tester role 은 testmode 빌드에서만 활성화 (roles_*.go + testmode_*.go).
ARG BOAN_BUILD_TAG=release
ENV BOAN_BUILD_TAG=${BOAN_BUILD_TAG}
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# BOAN_BUILD_TAG=testmode 이면 -tags=testmode 로 빌드, 아니면 빈 태그 (release).
RUN set -eux; \
    if [ "$BOAN_BUILD_TAG" = "testmode" ]; then TAGS=testmode; else TAGS=""; fi; \
    CGO_ENABLED=0 GOOS=linux go build -tags="$TAGS" -ldflags="-s -w" -o /boan-proxy ./cmd/proxy; \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /boan-audit ./cmd/audit; \
    echo "build mode: ${BOAN_BUILD_TAG}"

FROM alpine:3.21
RUN addgroup -S boan && adduser -S boan -G boan
RUN apk add --no-cache ca-certificates su-exec
WORKDIR /app
COPY --from=builder /boan-proxy /boan-audit /usr/local/bin/
RUN mkdir -p /etc/boan /data/users && chown -R boan:boan /etc/boan /data/users
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
# entrypoint runs as root, fixes /data/users ownership, then drops to boan via su-exec.
EXPOSE 18080 18081
ENTRYPOINT ["/entrypoint.sh"]
