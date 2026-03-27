package ratelimit

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type bucket struct {
	failures  int
	windowEnd time.Time
	mu        sync.Mutex
}

type Limiter struct {
	maxAttempts int
	windowSecs  int
	mu          sync.Mutex
	buckets     map[string]*bucket
}

func NewLimiter(maxAttempts, windowSecs int) *Limiter {
	return &Limiter{
		maxAttempts: maxAttempts,
		windowSecs:  windowSecs,
		buckets:     make(map[string]*bucket),
	}
}

func (l *Limiter) getBucket(key string) *bucket {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{}
		l.buckets[key] = b
	}
	return b
}

func (l *Limiter) RecordFailure(key string) bool {
	b := l.getBucket(key)
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if now.After(b.windowEnd) {
		b.failures = 0
		b.windowEnd = now.Add(time.Duration(l.windowSecs) * time.Second)
	}
	b.failures++
	return b.failures > l.maxAttempts
}

func (l *Limiter) Reset(key string) {
	b := l.getBucket(key)
	b.mu.Lock()
	b.failures = 0
	b.mu.Unlock()
}

func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ExtractIP(r)
		b := l.getBucket(ip)
		b.mu.Lock()
		now := time.Now()
		if now.After(b.windowEnd) {
			b.failures = 0
		}
		blocked := b.failures >= l.maxAttempts
		b.mu.Unlock()
		if blocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]any{
				"error":       "too_many_requests",
				"retry_after": l.windowSecs,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func ExtractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		ip := strings.TrimSpace(parts[0])
		if net.ParseIP(ip) != nil {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
