package audit

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

type Logger struct {
	tp       *sdktrace.TracerProvider
	endpoint string
	stats    struct {
		total   atomic.Uint64
		blocked atomic.Uint64
	}
}

func New(ctx context.Context, endpoint, orgID string) (*Logger, error) {
	l := &Logger{endpoint: endpoint}
	if endpoint == "" {
		return l, nil
	}
	exp, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName("boan-proxy"),
			attribute.String("org_id", orgID),
		)),
	)
	otel.SetTracerProvider(tp)
	l.tp = tp
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

func (l *Logger) Log(ctx context.Context, e Event) {
	l.stats.total.Add(1)
	if e.Action == "block:dlp" || e.Action == "block:network" || e.Action == "block:rbac" {
		l.stats.blocked.Add(1)
	}

	if l.tp == nil {
		log.Printf("audit: action=%s slevel=%d host=%s user=%s reason=%s hash=%s",
			e.Action, e.SLevel, e.Host, e.User, e.Reason, e.BodyHash)
		return
	}
	tracer := otel.Tracer("boan-proxy")
	_, span := tracer.Start(ctx, "boan.proxy.request")
	defer span.End()
	span.SetAttributes(
		attribute.String("boan.action", e.Action),
		attribute.Int("boan.slevel", e.SLevel),
		attribute.String("boan.body_hash", e.BodyHash),
		attribute.String("boan.host", e.Host),
		attribute.String("boan.user", e.User),
		attribute.String("boan.reason", e.Reason),
		attribute.String("boan.tool", e.Tool),
		attribute.String("boan.method", e.Method),
		attribute.String("boan.timestamp", time.Now().UTC().Format(time.RFC3339)),
	)
}

func (l *Logger) Shutdown(ctx context.Context) {
	if l.tp != nil {
		_ = l.tp.Shutdown(ctx)
	}
}

func (l *Logger) Endpoint() string {
	return l.endpoint
}

func (l *Logger) IsConnected() bool {
	return l.tp != nil
}

func (l *Logger) TotalEvents() uint64  { return l.stats.total.Load() }
func (l *Logger) BlockedEvents() uint64 { return l.stats.blocked.Load() }

func HashBody(body []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(body))
}
