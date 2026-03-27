package main

import (
	"log"
	"net/http"

	"github.com/samsung-sds/boanclaw/boan-onecli/internal/config"
	"github.com/samsung-sds/boanclaw/boan-onecli/internal/credclient"
	"github.com/samsung-sds/boanclaw/boan-onecli/internal/gateway"
	"github.com/samsung-sds/boanclaw/boan-onecli/internal/ratelimit"
	"github.com/samsung-sds/boanclaw/boan-onecli/internal/rewrite"
)

func main() {
	cfg := config.Load()

	cred := credclient.New(cfg.CredFilterURL, cfg.OrgID, cfg.CredentialName, cfg.CredentialType)
	limiter := ratelimit.NewLimiter(cfg.RateLimitRPM)
	rewriter := rewrite.New(cfg.ModelMap)

	gw, err := gateway.New(cfg.UpstreamBaseURL, cfg.OrgID, limiter, rewriter, cred)
	if err != nil {
		log.Fatalf("failed to create gateway: %v", err)
	}

	log.Printf("boan-onecli listening on %s -> %s (org=%s rpm=%d)",
		cfg.Listen, cfg.UpstreamBaseURL, cfg.OrgID, cfg.RateLimitRPM)

	if err := http.ListenAndServe(cfg.Listen, gw); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
