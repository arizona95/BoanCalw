//go:build testmode

package proxy

// tester_janitor.go — testmode 빌드에서만 컴파일.
//
// 배경: /api/test/session 이 발급한 role=tester 유저가 cleanup 안 된 채 admin UI 에 누적되는
// 문제 (사용자 발견: "git-probe@test.com 등 6 개 유저가 테스트 안 했는데 왜 남아있냐").
// VM janitor 는 cleanup-user 가 빠뜨린 GCP VM 만 정리하지만, tester user record 자체는 안 봄.
// 이 janitor 가 그 빈자리를 채운다 — 1 시간 지난 tester 는 deleteUserFully 로 통째 정리.
//
// 안전장치:
//   - role=tester 만 손댐. owner / user / 일반 admin 은 절대 안 건드림.
//   - 이 파일은 testmode 빌드에서만 컴파일. release 에서는 존재 자체가 없음.

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/roles"
)

const (
	defaultTesterTTL      = 60 * time.Minute
	testerJanitorInterval = 5 * time.Minute
)

// testerTTL — env 로 override 가능. BOAN_TESTER_TTL_MINUTES (정수). 없거나 잘못된 값이면
// 60 분 기본. 장기 E2E 테스트 (예: kill chain RDP 후 calc 검증) 시 사용자가 충분한 시간을
// 확보할 수 있도록.
func testerTTL() time.Duration {
	if v := os.Getenv("BOAN_TESTER_TTL_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Minute
		}
	}
	return defaultTesterTTL
}

func (s *Server) startTesterJanitor(ctx context.Context) {
	go func() {
		// 시작 시 한 번 — 재시작이 곧 sweep 트리거가 되도록.
		s.runTesterJanitorOnce(ctx)
		t := time.NewTicker(testerJanitorInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.runTesterJanitorOnce(ctx)
			}
		}
	}()
}

func (s *Server) runTesterJanitorOnce(ctx context.Context) {
	if s.users == nil {
		return
	}
	cutoff := time.Now().Add(-testerTTL())
	var toReap []string
	for _, u := range s.users.List() {
		if !strings.EqualFold(string(u.Role), string(roles.Tester)) {
			continue
		}
		if u.CreatedAt.IsZero() {
			continue
		}
		if u.CreatedAt.Before(cutoff) {
			toReap = append(toReap, u.Email)
		}
	}
	for _, email := range toReap {
		age := time.Since(s.userCreatedAt(email)).Round(time.Minute)
		log.Printf("[tester-janitor] reaping expired tester %s (age=%s)", email, age)
		if _, err := s.deleteUserFully(ctx, email, ""); err != nil {
			log.Printf("[tester-janitor] delete failed for %s: %v", email, err)
		}
	}
	if len(toReap) > 0 {
		log.Printf("[tester-janitor] cycle complete: %d tester(s) reaped", len(toReap))
	}
}

func (s *Server) userCreatedAt(email string) time.Time {
	for _, u := range s.users.List() {
		if strings.EqualFold(u.Email, email) {
			return u.CreatedAt
		}
	}
	return time.Now()
}
