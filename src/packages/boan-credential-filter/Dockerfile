FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /boan-credential-filter .

FROM alpine:3.21
RUN addgroup -S boan && adduser -S boan -G boan
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /boan-credential-filter /usr/local/bin/
RUN mkdir -p /etc/boan-cred && chown -R boan:boan /etc/boan-cred
USER boan
EXPOSE 8082
ENTRYPOINT ["boan-credential-filter"]
