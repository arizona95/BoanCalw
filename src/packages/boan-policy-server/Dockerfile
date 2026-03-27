FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /boan-policy-server .

FROM alpine:3.21
RUN addgroup -S boan && adduser -S boan -G boan
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /boan-policy-server /usr/local/bin/
RUN mkdir -p /data/policies /etc/boan-policy && chown -R boan:boan /data /etc/boan-policy
USER boan
EXPOSE 8080
ENTRYPOINT ["boan-policy-server"]
