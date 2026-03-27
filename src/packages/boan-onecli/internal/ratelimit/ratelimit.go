package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens    float64
	maxTokens float64
	lastRefil time.Time
	mu        sync.Mutex
}

func (b *bucket) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastRefil)
	b.tokens += elapsed.Minutes() * b.maxTokens
	if b.tokens > b.maxTokens {
		b.tokens = b.maxTokens
	}
	b.lastRefil = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type Limiter struct {
	rpm     float64
	buckets sync.Map
}

func NewLimiter(rpm int) *Limiter {
	return &Limiter{rpm: float64(rpm)}
}

func (l *Limiter) Allow(orgID string) bool {
	val, _ := l.buckets.LoadOrStore(orgID, &bucket{
		tokens:    l.rpm,
		maxTokens: l.rpm,
		lastRefil: time.Now(),
	})
	return val.(*bucket).allow()
}
