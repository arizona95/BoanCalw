package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/samsung-sds/boanclaw/boan-policy-server/internal/server"
)

func main() {
	cfg := server.LoadConfig()
	srv := server.New(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Start(ctx); err != nil {
		log.Fatalf("server: %v", err)
	}
}
