FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /boan-org-llm-proxy .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /boan-org-llm-proxy /usr/local/bin/
EXPOSE 8091
ENTRYPOINT ["boan-org-llm-proxy"]
