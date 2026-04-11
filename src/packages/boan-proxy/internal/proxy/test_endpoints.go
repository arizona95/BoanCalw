package proxy

// test_endpoints.go — TEST 모드에서만 등록되는 보조 endpoint 들.
//
// ⚠️  보안 경고:
//   여기 있는 endpoint 들은 인증 우회/임의 shell 실행 등 매우 강력한 권한.
//   반드시 cfg.TestMode == true (env: TEST=true 또는 BOAN_TEST_MODE=true) 일 때만
//   StartAdmin 에서 등록되며, prod compose 에서는 TEST 환경변수를 빼면 자동으로 사라진다.
//
// 등록 위치: admin.go StartAdmin 의 마지막 mux.HandleFunc 호출 직후.

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/auth"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/roles"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/userstore"
)

// registerTestEndpoints — cfg.TestMode 가 true 일 때만 호출됨.
// 모든 endpoint 는 prefix `/api/test/` 사용.
func (s *Server) registerTestEndpoints(mux *http.ServeMux) {
	// 부트 시 한 번 명시적으로 로그 — 운영자가 실수로 prod 에 띄웠는지 알아챌 수 있게.
	log.Printf("[boan-proxy] ⚠️  TEST mode endpoints registered (/api/test/*) — DO NOT enable in production")

	// ── /api/test/status ────────────────────────────────────────────────
	// 단순한 ping. test runner 가 "test 모드 활성 상태?" 를 첫 단계로 검사할 때 사용.
	mux.HandleFunc("/api/test/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"test_mode":     true,
			"owner_email":   s.cfg.OwnerEmail,
			"org_id":        s.cfg.OrgID,
			"admin_listen":  s.cfg.AdminListen,
			"openclaw_meta": "/opt/boanclaw-meta",
		})
	})

	// ── /api/test/session ───────────────────────────────────────────────
	// 임의 email + role + access_level 로 세션 발급. 사용자가 없으면 Upsert 해서 만들고,
	// access_level 도 강제 적용. 쿠키 set + body 로도 토큰 반환 (cookie jar 안 쓰는 도구 대응).
	mux.HandleFunc("/api/test/session", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
			return
		}
		var body struct {
			Email       string `json:"email"`
			Role        string `json:"role"`         // "owner" | "user"
			AccessLevel string `json:"access_level"` // "allow" | "ask" | "deny"
			OrgID       string `json:"org_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json: " + err.Error()})
			return
		}
		body.Email = strings.ToLower(strings.TrimSpace(body.Email))
		if body.Email == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email required"})
			return
		}
		if body.Role == "" {
			body.Role = "user"
		}
		if body.AccessLevel == "" {
			body.AccessLevel = "ask"
		}
		if !userstore.ValidAccessLevel(body.AccessLevel) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid access_level"})
			return
		}
		orgID := body.OrgID
		if orgID == "" {
			orgID = s.cfg.OrgID
			if orgID == "" {
				orgID = "test-org"
			}
		}
		if _, err := s.users.Upsert(body.Email, orgID, body.Role, userstore.StatusApproved); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "upsert: " + err.Error()})
			return
		}
		if err := s.users.SetAccessLevel(body.Email, userstore.AccessLevel(body.AccessLevel)); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "set_access_level: " + err.Error()})
			return
		}

		sess := &auth.Session{
			Sub:   body.Email,
			Email: body.Email,
			Name:  body.Email,
			Role:  roles.Normalize(roles.Role(body.Role)),
			OrgID: orgID,
		}
		token, err := s.authProv.CreateToken(sess)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token: " + err.Error()})
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "boan_session",
			Value:    token,
			Path:     "/",
			MaxAge:   8 * 3600,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":           true,
			"token":        token,
			"email":        body.Email,
			"role":         string(sess.Role),
			"org_id":       orgID,
			"access_level": body.AccessLevel,
		})
	})

	// ── /api/test/cleanup-user ──────────────────────────────────────────
	// 테스트 사용자 강제 삭제. role 보호 (owner 삭제 불가) 도 우회 — runner 가 실수로
	// 운영 owner 를 지정하지 않게 호출자 책임.
	mux.HandleFunc("/api/test/cleanup-user", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
			return
		}
		var body struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		body.Email = strings.ToLower(strings.TrimSpace(body.Email))
		if body.Email == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email required"})
			return
		}
		// 안전장치: owner email 은 거부.
		if strings.EqualFold(body.Email, s.cfg.OwnerEmail) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "cannot delete owner via test endpoint"})
			return
		}
		err := s.users.Delete(body.Email)
		if err != nil && err != userstore.ErrNotFound {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})

	// ── /api/test/sandbox-exec ──────────────────────────────────────────
	// boan-proxy 는 boan-sandbox 컨테이너 안에서 동작 → 여기서 sh -c 를 돌리면
	// 그 명령은 sandbox 내부에서 실행된다. HTTP_PROXY 환경변수가 sandbox 에
	// 설정되어 있으므로 curl 같은 outbound 는 boan-proxy 의 network gate 를 통과한다.
	// → network gate 의 실제 차단/허용을 호스트에서 바로 검증할 수 있는 유일한 통로.
	mux.HandleFunc("/api/test/sandbox-exec", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
			return
		}
		var body struct {
			Cmd     string `json:"cmd"`
			Timeout int    `json:"timeout"` // seconds, default 10, max 30
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
			return
		}
		body.Cmd = strings.TrimSpace(body.Cmd)
		if body.Cmd == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cmd required"})
			return
		}
		if body.Timeout <= 0 {
			body.Timeout = 10
		}
		if body.Timeout > 30 {
			body.Timeout = 30
		}

		ctx, cancel := context.WithTimeout(r.Context(), time.Duration(body.Timeout)*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, "sh", "-c", body.Cmd)
		// HTTP_PROXY 등은 process env 에서 자동 상속됨 (sandbox 가 그렇게 띄워져 있음)
		start := time.Now()
		stdoutBuf := newCapBuf(16 * 1024)
		stderrBuf := newCapBuf(16 * 1024)
		cmd.Stdout = stdoutBuf
		cmd.Stderr = stderrBuf
		err := cmd.Run()
		duration := time.Since(start)

		exitCode := 0
		errStr := ""
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
				errStr = err.Error()
			}
		}
		if ctx.Err() == context.DeadlineExceeded {
			errStr = "timeout"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":          err == nil,
			"stdout":      stdoutBuf.String(),
			"stderr":      stderrBuf.String(),
			"exit_code":   exitCode,
			"duration_ms": duration.Milliseconds(),
			"error":       errStr,
		})
	})

	// ── /api/test/policy-raw ────────────────────────────────────────────
	// 정책 store 의 raw JSON 을 그대로 dump. fetch / 캐시 / 서명 검증 우회.
	// 운영자가 PATCH 한 정책이 실제로 store 에 저장되었는지 확인하는 용도.
	mux.HandleFunc("/api/test/policy-raw", func(w http.ResponseWriter, r *http.Request) {
		// 정책 서버는 별도 HTTP 서비스이므로 그쪽 raw API 를 그대로 프록시한다.
		// (현재 코드에서 store 를 직접 import 안 하므로 HTTP 패스스루가 가장 단순)
		if s.cfg.PolicyURL == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no policy url configured"})
			return
		}
		org := r.URL.Query().Get("org")
		if org == "" {
			org = s.cfg.OrgID
		}
		kind := r.URL.Query().Get("kind")
		if kind == "" {
			kind = "network"
		}
		url := strings.TrimRight(s.cfg.PolicyURL, "/") + "/org/" + org + "/v1/policies/" + kind
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, url, nil)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})
}

// ── helper: cap-buffer (max N bytes, then drop) ─────────────────────────────

type capBuf struct {
	max int
	buf []byte
}

func newCapBuf(max int) *capBuf { return &capBuf{max: max, buf: make([]byte, 0, 1024)} }

func (c *capBuf) Write(p []byte) (int, error) {
	if len(c.buf) >= c.max {
		return len(p), nil
	}
	room := c.max - len(c.buf)
	if room > len(p) {
		room = len(p)
	}
	c.buf = append(c.buf, p[:room]...)
	return len(p), nil
}

func (c *capBuf) String() string { return string(c.buf) }

// ── helpers: JSON / IO / log banner ─────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
