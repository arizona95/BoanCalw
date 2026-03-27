package router

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync/atomic"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/dlp"
)

type Router struct {
	securityURL  *url.URL
	usabilityURL *url.URL
	stats        struct {
		toSecurity  atomic.Uint64
		toUsability atomic.Uint64
	}
}

func New(securityAgent, usabilityAgent string) (*Router, error) {
	sec, err := url.Parse(securityAgent)
	if err != nil {
		return nil, err
	}
	r := &Router{securityURL: sec}
	if usabilityAgent != "" {
		use, err := url.Parse(usabilityAgent)
		if err != nil {
			return nil, err
		}
		r.usabilityURL = use
	}
	return r, nil
}

func (r *Router) Route(req *http.Request, level dlp.SLevel) *httputil.ReverseProxy {
	if r.shouldRouteSecure(req, level) {
		r.stats.toSecurity.Add(1)
		return newProxy(r.securityURL)
	}
	if r.usabilityURL != nil {
		r.stats.toUsability.Add(1)
		return newProxy(r.usabilityURL)
	}
	r.stats.toSecurity.Add(1)
	return newProxy(r.securityURL)
}

func (r *Router) shouldRouteSecure(req *http.Request, level dlp.SLevel) bool {
	if req.Header.Get("X-Boan-Force") == "secure" {
		return true
	}
	return level >= dlp.SLevel2
}

func (r *Router) SecurityRouted() uint64  { return r.stats.toSecurity.Load() }
func (r *Router) UsabilityRouted() uint64 { return r.stats.toUsability.Load() }

func newProxy(target *url.URL) *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(target)
	original := p.Director
	p.Director = func(req *http.Request) {
		original(req)
		req.Header.Set("X-Forwarded-By", "boan-proxy")
	}
	return p
}
