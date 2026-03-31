FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /boan-whitelist-proxy .

FROM alpine:3.21
RUN addgroup -S boan && adduser -S boan -G boan
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /boan-whitelist-proxy /usr/local/bin/
USER boan
EXPOSE 8085
ENTRYPOINT ["boan-whitelist-proxy"]
