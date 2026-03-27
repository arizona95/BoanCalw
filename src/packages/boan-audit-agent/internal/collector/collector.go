package collector

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"

	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

type SpanRecord struct {
	Timestamp time.Time `json:"timestamp"`
	TraceID   string    `json:"trace_id"`
	SpanID    string    `json:"span_id"`
	Name      string    `json:"name"`
	Action    string    `json:"action"`
	SLevel    string    `json:"s_level"`
	Host      string    `json:"host"`
	User      string    `json:"user"`
	Reason    string    `json:"reason"`
}

type Collector struct {
	collectortracepb.UnimplementedTraceServiceServer
	mu      sync.Mutex
	records []SpanRecord
	logPath string
}

func New(logPath string) *Collector {
	return &Collector{logPath: logPath}
}

func (c *Collector) Export(_ context.Context, req *collectortracepb.ExportTraceServiceRequest) (*collectortracepb.ExportTraceServiceResponse, error) {
	for _, rs := range req.ResourceSpans {
		for _, ss := range rs.ScopeSpans {
			for _, span := range ss.Spans {
				rec := SpanRecord{
					Timestamp: time.Now().UTC(),
					TraceID:   hex.EncodeToString(span.TraceId),
					SpanID:    hex.EncodeToString(span.SpanId),
					Name:      span.Name,
				}
				for _, attr := range span.Attributes {
					val := attr.Value.GetStringValue()
					switch attr.Key {
					case "boan.action":
						rec.Action = val
					case "boan.slevel":
						rec.SLevel = val
					case "boan.host":
						rec.Host = val
					case "boan.user":
						rec.User = val
					case "boan.reason":
						rec.Reason = val
					}
				}
				c.mu.Lock()
				c.records = append(c.records, rec)
				c.mu.Unlock()
				c.appendToLog(rec)
			}
		}
	}
	return &collectortracepb.ExportTraceServiceResponse{}, nil
}

func (c *Collector) Records() []SpanRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]SpanRecord, len(c.records))
	copy(out, c.records)
	return out
}

func (c *Collector) RecordsSince(t time.Time) []SpanRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []SpanRecord
	for _, r := range c.records {
		if r.Timestamp.After(t) {
			out = append(out, r)
		}
	}
	return out
}

func (c *Collector) appendToLog(rec SpanRecord) {
	f, err := os.OpenFile(c.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	json.NewEncoder(f).Encode(rec)
}
