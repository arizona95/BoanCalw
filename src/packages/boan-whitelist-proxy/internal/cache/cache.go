package cache

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

type Entry struct {
	Response  string
	CreatedAt time.Time
	HitCount  int
	TTL       time.Duration
}

type candidateEntry struct {
	response string
	count    int
	lastSeen time.Time
}

type Store struct {
	mu         sync.RWMutex
	whitelist  map[string]*Entry
	candidates map[string]*candidateEntry
	promoteAt  int
	defaultTTL time.Duration
}

func NewStore(promoteThreshold int) *Store {
	return &Store{
		whitelist:  make(map[string]*Entry),
		candidates: make(map[string]*candidateEntry),
		promoteAt:  promoteThreshold,
		defaultTTL: 1 * time.Hour,
	}
}

func (s *Store) key(sentence string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(sentence)))
}

func (s *Store) Get(sentence string) (string, bool) {
	k := s.key(sentence)
	s.mu.RLock()
	e, ok := s.whitelist[k]
	s.mu.RUnlock()
	if !ok {
		return "", false
	}
	if e.TTL > 0 && time.Since(e.CreatedAt) > e.TTL {
		s.mu.Lock()
		delete(s.whitelist, k)
		s.mu.Unlock()
		return "", false
	}
	s.mu.Lock()
	e.HitCount++
	s.mu.Unlock()
	return e.Response, true
}

func (s *Store) AddCandidate(sentence, response string) {
	k := s.key(sentence)
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.candidates[k]; ok {
		c.count++
		c.lastSeen = time.Now()
		c.response = response
	} else {
		s.candidates[k] = &candidateEntry{
			response: response,
			count:    1,
			lastSeen: time.Now(),
		}
	}
	if s.candidates[k].count >= s.promoteAt {
		s.whitelist[k] = &Entry{
			Response:  s.candidates[k].response,
			CreatedAt: time.Now(),
			TTL:       s.defaultTTL,
		}
		delete(s.candidates, k)
	}
}

func (s *Store) Evict() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for k, e := range s.whitelist {
		if e.TTL > 0 && time.Since(e.CreatedAt) > e.TTL {
			delete(s.whitelist, k)
			count++
		}
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for k, c := range s.candidates {
		if c.lastSeen.Before(cutoff) {
			delete(s.candidates, k)
			count++
		}
	}
	return count
}

func (s *Store) Stats() (whitelisted, candidates int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.whitelist), len(s.candidates)
}
