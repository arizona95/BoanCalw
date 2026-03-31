FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /boan-audit-agent .

FROM alpine:3.21
RUN addgroup -S boan && adduser -S boan -G boan
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /boan-audit-agent /usr/local/bin/
RUN mkdir -p /data/audit && chown -R boan:boan /data
USER boan
EXPOSE 4317
ENTRYPOINT ["boan-audit-agent"]
