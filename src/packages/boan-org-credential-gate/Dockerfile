FROM golang:1.23-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git
COPY go.mod ./
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -ldflags="-s -w" -o /boan-org-credential-gate .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /boan-org-credential-gate /usr/local/bin/
EXPOSE 8092
ENTRYPOINT ["boan-org-credential-gate"]
