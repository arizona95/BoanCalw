FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /boan-proxy ./cmd/proxy
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /boan-audit ./cmd/audit

FROM alpine:3.21
RUN addgroup -S boan && adduser -S boan -G boan
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /boan-proxy /boan-audit /usr/local/bin/
RUN mkdir -p /etc/boan /data/users && chown -R boan:boan /etc/boan /data/users
USER boan
EXPOSE 18080 18081
ENTRYPOINT ["boan-proxy"]
