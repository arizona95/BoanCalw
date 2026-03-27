FROM golang:1.21-alpine AS builder
WORKDIR /src
COPY go.mod .
RUN go mod download
COPY . .
RUN go build -o /boan-onecli .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=builder /boan-onecli /usr/local/bin/boan-onecli
EXPOSE 8083
USER nobody
ENTRYPOINT ["boan-onecli"]
