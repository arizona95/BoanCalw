package proxy

// user_delete.go — 사용자 완전 삭제 + bound_user 정리.
//
// 배경: 예전 `/api/test/cleanup-user` 가 local userstore 만 지우고 GCP VM 은 그대로
// 남겨서 cost leak 발생 (4 개 테스트 VM 이 며칠씩 돌아감 → 사용자 수동 발견). 이 파일은
// admin DELETE 와 test cleanup 양쪽이 같은 코드 경로를 타도록 강제 — VM 정리는 한곳에서만
// 정의되고, 호출자가 빠뜨릴 수 없게 한다.

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/userstore"
)

// clearBoundUserFile — bound_user 파일이 email 과 일치하면 제거.
// 안 그러면 같은 PC 에서 다른 사용자가 로그인 시도 시 device-locked 메시지로 차단됨.
func (s *Server) clearBoundUserFile(email string) {
	if strings.TrimSpace(s.cfg.UserDataDir) == "" {
		return
	}
	path := filepath.Join(s.cfg.UserDataDir, "bound_user")
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	current := strings.TrimSpace(strings.ToLower(string(raw)))
	target := strings.TrimSpace(strings.ToLower(email))
	if current == target {
		_ = os.Remove(path)
		log.Printf("[user-delete] bound_user file cleared (was %s)", current)
	}
}

// deleteUserFully — 사용자의 GCP VM + 로컬 record + bound_user + cloud org server 까지
// 모두 정리하는 단일 진입점. admin DELETE 와 test cleanup-user 가 둘 다 이걸 호출해야
// 한다 (cost leak 재발 방지).
//
// 실패 정책:
//   - GCP VM 삭제 실패: log + 계속 진행 (VM 이 이미 없을 수도 있고, GCP 일시 장애도 OK).
//     janitor goroutine 이 다음 사이클에 다시 시도.
//   - local userstore 없음: OK (idempotent).
//   - cloud org server 404: warning 만 반환, ok=true.
//   - cloud org server 그 외 실패: error 반환.
func (s *Server) deleteUserFully(ctx context.Context, email, orgID string) (warning string, err error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", fmt.Errorf("email required")
	}
	if orgID == "" {
		orgID = s.cfg.OrgID
	}

	// 1) GCP VM 삭제 — workstation info 는 local 우선, 없으면 cloud org server.
	if s.workstations != nil {
		var ws *userstore.Workstation
		if local, _ := s.users.Workstation(email); local != nil {
			ws = local
		} else if s.orgs != nil {
			if remoteUsers, e := s.orgs.ClientFor(orgID).ListUsers(orgID); e == nil {
				for _, ru := range remoteUsers {
					if strings.EqualFold(ru.Email, email) && ru.Workstation != nil && ru.Workstation.InstanceID != "" {
						ws = &userstore.Workstation{
							Provider:   ru.Workstation.Provider,
							Platform:   ru.Workstation.Platform,
							InstanceID: ru.Workstation.InstanceID,
							Region:     ru.Workstation.Region,
						}
						break
					}
				}
			}
		}
		// ws 가 nil 이어도 Delete 호출 — gcp provisioner 는 email 슬러그로 instance name 추론 → 404 면 noop.
		if ws == nil {
			ws = &userstore.Workstation{}
		}
		if e := s.workstations.Delete(ctx, email, orgID, ws); e != nil {
			log.Printf("[user-delete] workstation delete failed for %s (proceeding): %v", email, e)
		} else {
			log.Printf("[user-delete] workstation deleted for %s (instance=%q)", email, ws.InstanceID)
		}
	}

	// 2) local userstore (idempotent)
	_ = s.users.Delete(email)

	// 2a) bound_user 정리
	s.clearBoundUserFile(email)

	// 3) cloud org server — 진실의 원천
	if s.orgs != nil {
		if e := s.orgs.ClientFor(orgID).DeleteUser(orgID, email); e != nil {
			if strings.Contains(e.Error(), "404") {
				log.Printf("[user-delete] org server 404 (already gone) for %s — treated as success", email)
				return "user 가 cloud org server 에는 없었음 (로컬/VM 만 정리됨).", nil
			}
			return "", fmt.Errorf("org server 삭제 실패: %w", e)
		}
	}
	return "", nil
}
