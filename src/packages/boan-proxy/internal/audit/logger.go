package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

type Logger struct {
	endpoint string
	client   *http.Client
	stats    struct {
		total   atomic.Uint64
		blocked atomic.Uint64
	}
}

func New(_ context.Context, endpoint, _ string) (*Logger, error) {
	l := &Logger{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 2 * time.Second},
	}
	return l, nil
}

type Event struct {
	Action   string
	SLevel   int
	BodyHash string
	Host     string
	User     string
	Reason   string
	Tool     string
	Method   string
}

type auditRecord struct {
	Action    string `json:"action"`
	SLevel    int    `json:"slevel"`
	BodyHash  string `json:"body_hash"`
	Host      string `json:"host"`
	User      string `json:"user"`
	Reason    string `json:"reason"`
	Tool      string `json:"tool"`
	Method    string `json:"method"`
	Timestamp string `json:"timestamp"`
}

func (l *Logger) Log(_ context.Context, e Event) {
	l.stats.total.Add(1)
	if e.Action == "block:dlp" || e.Action == "block:network" || e.Action == "block:rbac" {
		l.stats.blocked.Add(1)
	}

	rec := auditRecord{
		Action:    e.Action,
		SLevel:    e.SLevel,
		BodyHash:  e.BodyHash,
		Host:      e.Host,
		User:      e.User,
		Reason:    e.Reason,
		Tool:      e.Tool,
		Method:    e.Method,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	log.Printf("audit: action=%s slevel=%d host=%s user=%s reason=%s",
		e.Action, e.SLevel, e.Host, e.User, e.Reason)

	if l.endpoint == "" {
		return
	}

	go func() {
		body, _ := json.Marshal(rec)
		resp, err := l.client.Post(l.endpoint+"/audit", "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("audit send error: %v", err)
			return
		}
		resp.Body.Close()
	}()
}

func (l *Logger) Shutdown(_ context.Context) {}

func (l *Logger) Endpoint() string    { return l.endpoint }
func (l *Logger) IsConnected() bool   { return l.endpoint != "" }
func (l *Logger) TotalEvents() uint64  { return l.stats.total.Load() }
func (l *Logger) BlockedEvents() uint64 { return l.stats.blocked.Load() }

func HashBody(body []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(body))
}
