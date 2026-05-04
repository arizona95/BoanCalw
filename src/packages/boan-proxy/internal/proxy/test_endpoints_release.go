//go:build !testmode

// test_endpoints_release.go — release 빌드 stub. `/api/test/*` 엔드포인트는 존재
// 자체가 없음. 호출부 (admin.go) 가 양쪽 모드 모두 컴파일되도록 stub 메서드 제공.

package proxy

import "net/http"

// registerTestEndpoints — release 빌드에서는 아무것도 등록하지 않는다.
func (s *Server) registerTestEndpoints(_ *http.ServeMux) {}
