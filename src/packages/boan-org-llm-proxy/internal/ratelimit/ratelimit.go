// Package ratelimit provides a simple per-key sliding window counter.
// Used to cap requests per device_id on /v1/forward so a runaway agent
// loop can't blow through the LLM quota.
package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	mu       sync.Mutex
	window   time.Duration
	limit    int
	requests map[string][]time.Time
}

func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		window:   window,
		limit:    limit,
		requests: make(map[string][]time.Time),
	}
}

// Allow records an attempt for key at time now and returns whether it
// fits within the (limit, window). Expired entries are pruned.
func (l *Limiter) Allow(key string) bool {
	if l == nil || l.limit <= 0 {
		return true
	}
	now := time.Now()
	cutoff := now.Add(-l.window)

	l.mu.Lock()
	defer l.mu.Unlock()

	hist := l.requests[key]
	kept := hist[:0]
	for _, t := range hist {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.limit {
		l.requests[key] = kept
		return false
	}
	kept = append(kept, now)
	l.requests[key] = kept
	return true
}

// Prune drops keys with empty recent history (prevents unbounded map growth).
func (l *Limiter) Prune() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-l.window)
	for k, hist := range l.requests {
		kept := hist[:0]
		for _, t := range hist {
			if t.After(cutoff) {
				kept = append(kept, t)
			}
		}
		if len(kept) == 0 {
			delete(l.requests, k)
		} else {
			l.requests[k] = kept
		}
	}
}
