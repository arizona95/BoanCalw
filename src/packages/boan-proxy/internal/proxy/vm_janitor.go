package proxy

// vm_janitor.go — 고아 GCP VM reaper.
//
// 배경: cleanup-user 버그로 4 개 테스트 VM 이 며칠 동안 살아있었음. 이 janitor 는 비용이
// 영원히 누적되지 않도록 하는 안전망. cleanup 코드가 한 번 더 빠뜨려도, 정기적 sweep 으로
// "이 VM 의 사용자가 아직 존재하는가?" 를 확인해서 NO 면 삭제.
//
// 안전 정책:
//   - boanclaw label (`boanclaw-user-email`) 이 붙은 인스턴스만 손댐. 다른 팀 VM 은 절대 손대지 않음.
//   - 생성 후 grace period (기본 30 분) 가 지난 VM 만 reap 대상 — 신규 provisioning 도중인 VM
//     이 user 등록 직전에 reap 되는 경쟁 상태 방지.
//   - owner 이메일 의 VM 은 절대 reap 하지 않음 (이중 안전장치).

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/userstore"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/workstation"
)

const (
	janitorInterval    = 10 * time.Minute
	janitorGracePeriod = 30 * time.Minute
)

// startVMJanitor — 별도 goroutine 으로 실행. ctx 가 cancel 되면 종료.
// proxy.New 에서 호출. tester 또는 production 빌드 둘 다 동작 (cost leak 은 양쪽 다 위험).
func (s *Server) startVMJanitor(ctx context.Context) {
	if s.workstations == nil {
		return
	}
	go func() {
		// 시작 시 한 번 — proxy 재시작이 트리거가 되도록.
		s.runVMJanitorOnce(ctx)
		t := time.NewTicker(janitorInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.runVMJanitorOnce(ctx)
			}
		}
	}()
}

// runVMJanitorOnce — 한번 sweep. 외부에서 admin endpoint 로 강제 트리거할 수도 있게 분리.
func (s *Server) runVMJanitorOnce(ctx context.Context) {
	instances, err := s.workstations.ListManagedInstances(ctx)
	if err != nil {
		log.Printf("[vm-janitor] list failed: %v — skipping this cycle", err)
		return
	}
	if len(instances) == 0 {
		return
	}

	// dual-process safety — sandbox-embedded proxy 와 standalone 컨테이너 가 같은
	// users.json 을 공유 하지만 각자 in-memory cache 는 별도. reaper 가 stale cache 로
	// 신규 VM 을 orphan 으로 오인하고 삭제한 사고 (v10) 가 있어 매 sweep 직전 reload.
	if err := s.users.Reload(); err != nil {
		log.Printf("[vm-janitor] users reload failed: %v — proceeding with cached state (may misdetect orphans)", err)
	}

	// 현재 살아있는 사용자 이메일 집합 (label 형식 으로 normalize) — local + cloud org server.
	live := make(map[string]bool)
	for _, u := range s.users.List() {
		live[workstation.LabelEmail(u.Email)] = true
	}
	if s.orgs != nil {
		// 모든 org 의 user 까지 합집합 — multi-org 환경에서 reaper 가 다른 org VM 을 잘못 지우는 것 방지.
		for _, entry := range s.orgs.List() {
			if remoteUsers, e := s.orgs.ClientFor(entry.OrgID).ListUsers(entry.OrgID); e == nil {
				for _, ru := range remoteUsers {
					live[workstation.LabelEmail(ru.Email)] = true
				}
			}
		}
	}
	// owner 이메일도 명시적으로 보호.
	if s.cfg.OwnerEmail != "" {
		live[workstation.LabelEmail(s.cfg.OwnerEmail)] = true
	}

	now := time.Now()
	reaped := 0
	for _, inst := range instances {
		emailLbl := strings.ToLower(strings.TrimSpace(inst.Email))
		if emailLbl == "" {
			continue // safety — label 없으면 boanclaw 소속이 아닐 수 있음.
		}
		if live[emailLbl] {
			continue // 사용자가 살아있음 — VM 유지.
		}
		// 막 만들어진 VM (provisioning 직후) 보호.
		if !inst.CreationTime.IsZero() && now.Sub(inst.CreationTime) < janitorGracePeriod {
			log.Printf("[vm-janitor] %s (label email=%s) 사용자 없음이지만 grace period 내 — skip", inst.Name, emailLbl)
			continue
		}
		// 실제 삭제. fakeWorkstation 으로 Delete 호출 (instance name 만 채워주면 됨).
		log.Printf("[vm-janitor] reaping orphan VM %s (label email=%s, age=%s)",
			inst.Name, emailLbl, now.Sub(inst.CreationTime).Round(time.Minute))
		fakeWs := &userstore.Workstation{InstanceID: inst.Name}
		if err := s.workstations.Delete(ctx, emailLbl, inst.OrgID, fakeWs); err != nil {
			log.Printf("[vm-janitor] delete %s failed: %v", inst.Name, err)
			continue
		}
		reaped++
	}
	if reaped > 0 {
		log.Printf("[vm-janitor] cycle complete: %d orphan VM(s) reaped", reaped)
	}
}
