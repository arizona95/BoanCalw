package server

import (
	"sync"
	"sync/atomic"
)

// Broker fans out policy-update events to SSE subscribers.
//
// One Broker per process. Subscribers register with Subscribe(orgID) which
// returns a buffered channel and an unsubscribe func. Whenever updatePolicy
// saves a new revision, it calls Publish(orgID, payload) — the broker pushes
// payload to every subscriber for that org. Non-blocking: if a subscriber's
// buffer is full the event is dropped for that subscriber (clients fall back
// to the 60s polling cycle to recover).
//
// Memory only — Cloud Run min-instances=1 + single revision keeps all
// subscribers attached to the same process. Multi-instance fan-out would
// require Pub/Sub; out of scope here.
type Broker struct {
	mu    sync.RWMutex
	subs  map[string]map[uint64]chan []byte
	nextID atomic.Uint64
}

func NewBroker() *Broker {
	return &Broker{subs: make(map[string]map[uint64]chan []byte)}
}

// Subscribe registers a new subscriber for orgID. Returns:
//   - ch: buffered channel receiving JSON payloads (one per update).
//   - cancel: closes the channel and removes it from the broker.
func (b *Broker) Subscribe(orgID string) (chan []byte, func()) {
	id := b.nextID.Add(1)
	ch := make(chan []byte, 8)
	b.mu.Lock()
	if _, ok := b.subs[orgID]; !ok {
		b.subs[orgID] = make(map[uint64]chan []byte)
	}
	b.subs[orgID][id] = ch
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		if m, ok := b.subs[orgID]; ok {
			delete(m, id)
			if len(m) == 0 {
				delete(b.subs, orgID)
			}
		}
		b.mu.Unlock()
		close(ch)
	}
}

// Publish fans payload out to all subscribers of orgID. Non-blocking: if a
// subscriber's channel is full the event is dropped (its next polling tick
// will recover the missed update).
func (b *Broker) Publish(orgID string, payload []byte) {
	b.mu.RLock()
	subs := b.subs[orgID]
	chans := make([]chan []byte, 0, len(subs))
	for _, ch := range subs {
		chans = append(chans, ch)
	}
	b.mu.RUnlock()
	for _, ch := range chans {
		select {
		case ch <- payload:
		default:
			// Subscriber too slow; let it recover via polling.
		}
	}
}

// SubscriberCount returns the current number of subscribers per orgID, for
// /healthz observability.
func (b *Broker) SubscriberCount(orgID string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.subs[orgID])
}
