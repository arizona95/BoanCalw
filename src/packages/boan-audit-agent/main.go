package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"

	"github.com/samsung-sds/boanclaw/boan-audit-agent/internal/collector"
	"github.com/samsung-sds/boanclaw/boan-audit-agent/internal/reporter"
)

func main() {
	listen := env("BOAN_LISTEN", ":4317")
	logPath := env("BOAN_LOG_PATH", "/data/audit/spans.jsonl")

	os.MkdirAll("/data/audit", 0700)

	col := collector.New(logPath)
	rep := reporter.New(col, 5*time.Minute)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go rep.Start(ctx)

	lis, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	srv := grpc.NewServer()
	collectortracepb.RegisterTraceServiceServer(srv, col)

	go func() {
		<-ctx.Done()
		srv.GracefulStop()
	}()

	log.Printf("boan-audit-agent listening on %s (gRPC)", listen)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
