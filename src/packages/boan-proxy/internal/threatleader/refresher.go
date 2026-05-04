package threatleader

import (
	"context"
	"log"
	"time"
)

const (
	// 데일리 cron — 24h 주기. OSV bucket 자체는 매시간+ regenerate 되지만 행정상 1일 1회.
	refreshInterval = 24 * time.Hour
	// 최근 advisory 만 추출 — 7일.
	lookbackWindow = 7 * 24 * time.Hour
	// UI 표시 후보 수.
	topN = 5
)

// Refresher — 백그라운드 24h cron + 즉시 트리거.
type Refresher struct {
	store     *Store
	trigger   chan struct{}
}

func NewRefresher(store *Store) *Refresher {
	return &Refresher{
		store:   store,
		trigger: make(chan struct{}, 1),
	}
}

// Start — proxy.New 끝에서 호출. ctx cancel 시 종료.
// 부팅 시 한 번 즉시 fetch (사용자가 admin UI 처음 열면 데이터 있게).
func (r *Refresher) Start(ctx context.Context) {
	go func() {
		// 시작 후 5 분 후에 첫 fetch — 부팅 직후 OSV 다운로드 (수십 MB) 로
		// 시작 단계 부담 안 주려고. 그 사이 UI 가 GET 호출하면 빈 latest 반환.
		time.Sleep(5 * time.Minute)
		r.RefreshOnce(ctx)
		t := time.NewTicker(refreshInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.trigger:
				r.RefreshOnce(ctx)
			case <-t.C:
				r.RefreshOnce(ctx)
			}
		}
	}()
}

// TriggerNow — UI 의 ↻ 즉시 탐색 버튼이 호출. non-blocking.
func (r *Refresher) TriggerNow() {
	select {
	case r.trigger <- struct{}{}:
	default:
		// 이미 트리거 대기 중 — drop.
	}
}

// RefreshOnce — 모든 ecosystem 의 OSV bucket fetch + select + store 갱신.
// 동기 호출도 가능 (수동 트리거 endpoint 가 결과 기다리고 싶을 때).
func (r *Refresher) RefreshOnce(ctx context.Context) error {
	log.Printf("[threat-leader] refresh start (ecosystems=%v)", Ecosystems)
	all := make([]Advisory, 0, 1024)
	for _, eco := range Ecosystems {
		ctx2, cancel := context.WithTimeout(ctx, 3*time.Minute)
		advs, err := FetchEcosystem(ctx2, eco, lookbackWindow)
		cancel()
		if err != nil {
			log.Printf("[threat-leader] fetch %s failed: %v", eco, err)
			continue
		}
		log.Printf("[threat-leader] fetched %s: %d advisories (modified <= %s)", eco, len(advs), lookbackWindow)
		all = append(all, advs...)
	}
	state := r.store.Snapshot()
	props := SelectTopProposals(all, topN, &state)
	if err := r.store.SetLatest(props); err != nil {
		log.Printf("[threat-leader] store save failed: %v", err)
		return err
	}
	log.Printf("[threat-leader] refresh done: %d top proposals", len(props))
	return nil
}
