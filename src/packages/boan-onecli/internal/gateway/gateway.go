package gateway

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/samsung-sds/boanclaw/boan-onecli/internal/credclient"
	"github.com/samsung-sds/boanclaw/boan-onecli/internal/ratelimit"
	"github.com/samsung-sds/boanclaw/boan-onecli/internal/rewrite"
)

type Gateway struct {
	orgID   string
	limiter *ratelimit.Limiter
	rewriter *rewrite.Rewriter
	cred    *credclient.Client
	proxy   *httputil.ReverseProxy
}

func New(
	upstreamURL string,
	orgID string,
	limiter *ratelimit.Limiter,
	rewriter *rewrite.Rewriter,
	cred *credclient.Client,
) (*Gateway, error) {
	upstream, err := url.Parse(upstreamURL)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.FlushInterval = -1

	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = upstream.Host
	}

	return &Gateway{
		orgID:    orgID,
		limiter:  limiter,
		rewriter: rewriter,
		cred:     cred,
		proxy:    proxy,
	}, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	if !g.limiter.Allow(g.orgID) {
		http.Error(w, `{"error":{"type":"rate_limit_error","message":"rate limit exceeded"}}`, http.StatusTooManyRequests)
		log.Printf("RATE_LIMITED method=%s path=%s org=%s", r.Method, r.URL.Path, g.orgID)
		return
	}

	originalModel, err := g.rewriter.RewriteBody(r)
	if err != nil {
		http.Error(w, `{"error":{"type":"internal_error","message":"failed to rewrite request"}}`, http.StatusInternalServerError)
		return
	}

	r.Header.Del("Authorization")
	r.Header.Del("x-api-key")

	if err := g.cred.InjectHeader(r); err != nil {
		http.Error(w, `{"error":{"type":"authentication_error","message":"failed to obtain credential"}}`, http.StatusInternalServerError)
		log.Printf("CRED_ERROR method=%s path=%s org=%s err=%v", r.Method, r.URL.Path, g.orgID, err)
		return
	}

	rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
	start := time.Now()
	g.proxy.ServeHTTP(rw, r)

	log.Printf("PROXY method=%s path=%s model=%s org=%s status=%d duration=%s",
		r.Method, r.URL.Path, originalModel, g.orgID, rw.statusCode, time.Since(start))
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
