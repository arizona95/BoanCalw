// Package policysync provides a single client that keeps a device-side
// in-memory copy of the policy-server's signed policy in sync via:
//
//   1. A long-lived SSE stream (/network-policy.stream) — sub-100ms push.
//   2. A polling fallback (/network-policy.json) at a configurable interval.
//
// Subscribers register an OnUpdate callback; every successful payload
// (initial fetch, SSE event, or poll tick) is decoded and dispatched to
// every registered handler. This collapses the duplicate stream-reader
// loops that used to live inside network.Gate so that other device-side
// consumers (guardrail cache, future policy-driven modules) plug into the
// same source instead of opening their own connections.
//
// The client is intentionally generic: callers pass a Decoder that maps
// the signed wire payload to whatever shape they want (Endpoint slice,
// guardrail rules, raw bytes…). Decoder failures are logged and skipped —
// one bad event must not stop later events from reaching healthy
// subscribers.
package policysync

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Decoder turns a raw signed payload (the bytes that arrive on the SSE
// `event: policy\ndata: <json>\n\n` stream or as the body of the polling
// GET) into a type the caller cares about. Returns an error if the bytes
// can't be parsed; the client logs and drops invalid payloads.
type Decoder[T any] func([]byte) (T, error)

// OnUpdate is the subscriber callback. Receives the latest decoded policy
// snapshot. Called from a single goroutine per Client so callbacks don't
// need to be reentrancy-safe with each other, but they SHOULD be quick
// (don't block the dispatch loop with long work — fan out yourself if
// needed).
type OnUpdate[T any] func(T)

// Client orchestrates SSE + polling fan-out for one (policyURL, orgID)
// pair. Create with New, register handlers with Subscribe, then call
// Start to kick off the goroutines. Stop by cancelling the context
// passed to Start.
type Client[T any] struct {
	policyURL string
	orgID     string
	orgToken  string
	pollEvery time.Duration
	httpc     *http.Client
	decode    Decoder[T]

	mu       sync.Mutex
	handlers []OnUpdate[T]
	last     T
	haveLast bool
}

// Config bundles the knobs callers tend to tweak. zero PollInterval
// defaults to 60s — the historical network.Gate cadence.
type Config[T any] struct {
	PolicyURL    string
	OrgID        string
	OrgToken     string
	PollInterval time.Duration
	HTTPClient   *http.Client
	Decode       Decoder[T]
}

func New[T any](cfg Config[T]) *Client[T] {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 60 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client[T]{
		policyURL: strings.TrimRight(cfg.PolicyURL, "/"),
		orgID:     cfg.OrgID,
		orgToken:  cfg.OrgToken,
		pollEvery: cfg.PollInterval,
		httpc:     cfg.HTTPClient,
		decode:    cfg.Decode,
	}
}

// Subscribe registers a callback. If a snapshot has already been received,
// the callback runs immediately so subscribers don't have to wait for the
// next event to know "what's the current value." Returns an unsubscribe
// function that removes the callback.
func (c *Client[T]) Subscribe(fn OnUpdate[T]) func() {
	c.mu.Lock()
	c.handlers = append(c.handlers, fn)
	idx := len(c.handlers) - 1
	last := c.last
	have := c.haveLast
	c.mu.Unlock()
	if have {
		fn(last)
	}
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if idx < len(c.handlers) {
			c.handlers[idx] = nil
		}
	}
}

// Latest returns the most recent decoded snapshot and whether one has
// arrived yet. Use this when you need a one-shot read without committing
// to a subscription (e.g. on a synchronous request path that wants to
// short-circuit before the first event lands).
func (c *Client[T]) Latest() (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last, c.haveLast
}

// Start runs the polling loop and the SSE loop. Both shut down when ctx
// is cancelled. The first polling tick fires immediately so subscribers
// have a value within a few hundred ms of startup, even before SSE
// connects.
func (c *Client[T]) Start(ctx context.Context) {
	if c.policyURL == "" || c.orgID == "" {
		return
	}
	go c.runStream(ctx)
	go c.runPoll(ctx)
}

func (c *Client[T]) runPoll(ctx context.Context) {
	c.pollOnce(ctx)
	ticker := time.NewTicker(c.pollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.pollOnce(ctx)
		}
	}
}

func (c *Client[T]) pollOnce(ctx context.Context) {
	url := fmt.Sprintf("%s/org/%s/network-policy.json", c.policyURL, c.orgID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return
	}
	if c.orgToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.orgToken)
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		log.Printf("policysync: poll failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("policysync: poll status %d", resp.StatusCode)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return
	}
	c.dispatch(body)
}

// runStream maintains the SSE connection with exponential backoff up to
// 30 s when reconnects fail. Polling continues independently as a safety
// net so a stuck stream doesn't blind the device to policy edits.
func (c *Client[T]) runStream(ctx context.Context) {
	backoff := 2 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		err := c.streamOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("policysync: stream disconnected (%v); retry in %s", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (c *Client[T]) streamOnce(ctx context.Context) error {
	url := fmt.Sprintf("%s/org/%s/network-policy.stream", c.policyURL, c.orgID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	if c.orgToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.orgToken)
	}
	streamClient := &http.Client{Transport: c.httpc.Transport}
	resp, err := streamClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	log.Printf("policysync: stream connected to %s", url)
	reader := bufio.NewReader(resp.Body)
	var dataBuf strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if dataBuf.Len() > 0 {
				payload := []byte(dataBuf.String())
				dataBuf.Reset()
				c.dispatch(payload)
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataBuf.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
}

// dispatch decodes a raw payload and pushes it to every live subscriber.
// Decode failures are logged and discarded — the next event has a fresh
// chance. Nil handlers (slot vacated by an Unsubscribe) are skipped.
func (c *Client[T]) dispatch(payload []byte) {
	if c.decode == nil {
		return
	}
	v, err := c.decode(payload)
	if err != nil {
		log.Printf("policysync: decode failed: %v", err)
		return
	}
	c.mu.Lock()
	c.last = v
	c.haveLast = true
	handlers := make([]OnUpdate[T], 0, len(c.handlers))
	for _, h := range c.handlers {
		if h != nil {
			handlers = append(handlers, h)
		}
	}
	c.mu.Unlock()
	for _, h := range handlers {
		h(v)
	}
}
