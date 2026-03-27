package reporter

import (
	"context"
	"encoding/json"
	"log"
	"sort"
	"time"

	"github.com/samsung-sds/boanclaw/boan-audit-agent/internal/collector"
)

type HostCount struct {
	Host  string `json:"host"`
	Count int    `json:"count"`
}

type Summary struct {
	Period      string         `json:"period"`
	TotalSpans  int            `json:"total_spans"`
	ByAction    map[string]int `json:"by_action"`
	BySLevel    map[string]int `json:"by_slevel"`
	TopBlocked  []HostCount    `json:"top_blocked_hosts"`
	GeneratedAt time.Time      `json:"generated_at"`
}

type Reporter struct {
	col      *collector.Collector
	interval time.Duration
}

func New(col *collector.Collector, interval time.Duration) *Reporter {
	return &Reporter{col: col, interval: interval}
}

func (r *Reporter) Start(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	var lastReport time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			summary := r.Generate(lastReport)
			lastReport = time.Now()
			raw, _ := json.MarshalIndent(summary, "", "  ")
			log.Printf("audit-report:\n%s", raw)
		}
	}
}

func (r *Reporter) Generate(since time.Time) Summary {
	records := r.col.RecordsSince(since)
	s := Summary{
		Period:      since.Format(time.RFC3339) + " ~ " + time.Now().Format(time.RFC3339),
		TotalSpans:  len(records),
		ByAction:    make(map[string]int),
		BySLevel:    make(map[string]int),
		GeneratedAt: time.Now().UTC(),
	}
	hostCounts := make(map[string]int)
	for _, rec := range records {
		if rec.Action != "" {
			s.ByAction[rec.Action]++
		}
		if rec.SLevel != "" {
			s.BySLevel[rec.SLevel]++
		}
		if rec.Host != "" && rec.Action == "blocked" {
			hostCounts[rec.Host]++
		}
	}
	for h, c := range hostCounts {
		s.TopBlocked = append(s.TopBlocked, HostCount{Host: h, Count: c})
	}
	sort.Slice(s.TopBlocked, func(i, j int) bool {
		return s.TopBlocked[i].Count > s.TopBlocked[j].Count
	})
	if len(s.TopBlocked) > 10 {
		s.TopBlocked = s.TopBlocked[:10]
	}
	return s
}
