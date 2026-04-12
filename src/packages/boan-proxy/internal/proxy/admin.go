package proxy

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/audit"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/auth"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/orgserver"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/roles"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/userstore"
)

// cuQueuedCmd is a computer-use command waiting to be executed by the browser.
type cuQueuedCmd struct {
	id     string
	params map[string]any
	done   chan []byte
}

// userRDPTransferDir — RDP virtual drive 가 마운트되는 사용자별 staging 디렉토리.
// boan-sandbox 와 boan-guacd 가 동일 볼륨(boan-rdp-transfer) 을 공유하므로
// 여기 쓴 파일은 사용자의 활성 Guacamole RDP 세션에서 BoanClaw 드라이브로 보임.
// 반대로 사용자가 RDP 안에서 BoanClaw 드라이브에 둔 파일도 여기서 읽힌다.
func userRDPTransferDir(root, email string) string {
	safe := strings.ToLower(strings.TrimSpace(email))
	if safe == "" {
		safe = "_anon"
	}
	// 경로 이스케이프 방어 — slash, backslash, dotdot 차단.
	safe = strings.NewReplacer("/", "_", "\\", "_", "..", "_").Replace(safe)
	return filepath.Join(root, safe)
}

// ensureRDPTransferDir — RDP staging 디렉토리를 생성하면서 guacd 가 쓸 수 있게
// 권한을 보장한다. boan-sandbox(uid 2000/boan)가 만든 디렉토리를
// boan-guacd(uid 1000/guacd)가 같은 named volume 으로 마운트해서 접근하기 때문에
// other 비트에 write 권한이 없으면 RDP 드라이브 업로드(Win → sandbox)가
// EACCES 로 실패한다. MkdirAll 은 process umask 의 영향을 받으므로
// 명시적으로 Chmod 를 한 번 더 호출해서 0o777 을 강제한다.
// (named volume 은 compose stack 내부 전용이고, 사용자별 email 디렉토리로
// 이미 격리되어 있어서 추가 노출 위험은 없음.)
func ensureRDPTransferDir(path string) error {
	if err := os.MkdirAll(path, 0o777); err != nil {
		return err
	}
	return os.Chmod(path, 0o777)
}

var (
	cuQueueMu     sync.Mutex
	cuPendingQueue []*cuQueuedCmd // waiting to be picked up by browser poll
	cuInFlight     []*cuQueuedCmd // picked up, waiting for result
)

// ── computer-use 최종 screenshot 보관 (chat 인젝트용) ──────────────────────
// inline base64 를 chat 메시지에 박으면 OpenClaw markdown 렌더러가 새로고침
// 후 긴 string 을 못 파싱해서 이미지가 깨진다. 대신 in-memory map 에 저장하고
// /api/computer-use/screenshot/{id}.jpg 로 서빙. inject 메시지엔 short URL 만.
//
// TTL: 6시간 (~24시간 사용자 세션 + 안전 마진).
// max entries: 200 (oldest evicted).
type cuScreenshot struct {
	jpegBytes []byte
	createdAt time.Time
}

var (
	cuScreenshotMu    sync.Mutex
	cuScreenshotStore = map[string]cuScreenshot{}
)

const cuScreenshotTTL = 6 * time.Hour
const cuScreenshotMaxEntries = 200

// storeChatScreenshot — JPEG bytes 를 저장하고 ID 반환. 호출측은 ID 로 URL 생성.
func storeChatScreenshot(jpeg []byte) string {
	idBytes := make([]byte, 8)
	crand.Read(idBytes)
	id := hex.EncodeToString(idBytes)
	now := time.Now()
	cuScreenshotMu.Lock()
	defer cuScreenshotMu.Unlock()
	cuScreenshotStore[id] = cuScreenshot{jpegBytes: jpeg, createdAt: now}
	// 간단한 GC: 만료 + 최대 개수 초과 시 오래된 것부터 제거
	if len(cuScreenshotStore) > cuScreenshotMaxEntries {
		oldest := ""
		oldestT := now
		for k, v := range cuScreenshotStore {
			if v.createdAt.Before(oldestT) {
				oldest = k
				oldestT = v.createdAt
			}
		}
		if oldest != "" {
			delete(cuScreenshotStore, oldest)
		}
	}
	for k, v := range cuScreenshotStore {
		if now.Sub(v.createdAt) > cuScreenshotTTL {
			delete(cuScreenshotStore, k)
		}
	}
	return id
}

func loadChatScreenshot(id string) ([]byte, bool) {
	cuScreenshotMu.Lock()
	defer cuScreenshotMu.Unlock()
	s, ok := cuScreenshotStore[id]
	if !ok {
		return nil, false
	}
	if time.Since(s.createdAt) > cuScreenshotTTL {
		delete(cuScreenshotStore, id)
		return nil, false
	}
	return s.jpegBytes, true
}

// ── Observability: 로깅/트레이싱 수집 ──────────────────────────────────────
type traceEntry struct {
	ID        string `json:"id"`
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`      // chat, guardrail, network, credential, file, system
	Direction string `json:"direction"` // inbound, outbound, internal
	Source    string `json:"source"`    // user email or service name
	Target    string `json:"target"`    // llm, gcp, policy-server, etc
	Summary   string `json:"summary"`   // 요약 (메시지 앞 200자)
	Decision  string `json:"decision"`  // allow, block, ask, n/a
	Gate      string `json:"gate"`      // G1, G2, G3, network, credential, none
	Duration  int64  `json:"duration_ms"`
	Meta      map[string]any `json:"meta,omitempty"`
}

var (
	traceMu    sync.Mutex
	traceStore []traceEntry
	traceMaxEntries = 500
)

func addTrace(t traceEntry) {
	if t.ID == "" {
		b := make([]byte, 8)
		crand.Read(b)
		t.ID = hex.EncodeToString(b)
	}
	if t.Timestamp == "" {
		t.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	traceMu.Lock()
	traceStore = append(traceStore, t)
	if len(traceStore) > traceMaxEntries {
		traceStore = traceStore[len(traceStore)-traceMaxEntries:]
	}
	traceMu.Unlock()
}

// credential 등록 추천 (소유자가 org-wide 로 등록; 전체 사용자가 자기 개인 키 등록 권고)
// fulfill 은 per-user (세션 email 기준 personal 키 생성) — recommendation 자체는 유지됨
type credentialRequest struct {
	ID          string `json:"id"`
	RoleName    string `json:"role_name"`   // credential role 이름 (예: openai-key)
	Description string `json:"description"` // 설명
	CreatedAt   string `json:"created_at"`
}

var (
	approvalsMu    sync.Mutex
	approvalsStore []map[string]any
	pendingCredentialApprovals = map[string][]credentialApprovalCandidate{}
	credReqMu      sync.Mutex
	credReqStore   []credentialRequest
	registryCredentialPatterns = []*regexp.Regexp{
		regexp.MustCompile(`-H\s+["']?(Authorization|authorization):\s*Bearer\s+([A-Za-z0-9\-_\.=]{16,})["']?`),
		regexp.MustCompile(`-H\s+["']?(x-api-key|X-Api-Key|x-goog-api-key):\s*([A-Za-z0-9\-_\.=]{16,})["']?`),
		regexp.MustCompile(`-H\s+["']?(api-key|Api-Key):\s*([A-Za-z0-9\-_\.=]{16,})["']?`),
	}
)

type credentialApprovalCandidate struct {
	Role        string
	Key         string
	Preview     string
	Fingerprint string
}

func credentialGateRoleName(rawKey, fingerprint string) string {
	shortFP := fingerprint
	if len(shortFP) > 8 {
		shortFP = shortFP[:8]
	}
	lower := strings.ToLower(strings.TrimSpace(rawKey))
	switch {
	case strings.HasPrefix(lower, "sk-ant-"):
		return "anthropic-apikey-" + shortFP
	case strings.HasPrefix(lower, "sk-proj-"), strings.HasPrefix(lower, "sk-"):
		return "openai-apikey-" + shortFP
	case strings.HasPrefix(lower, "ghp_"), strings.HasPrefix(lower, "github_pat_"):
		return "github-token-" + shortFP
	case strings.HasPrefix(rawKey, "AKIA"):
		return "aws-access-key-" + shortFP
	case strings.HasPrefix(rawKey, "AIza"):
		return "google-apikey-" + shortFP
	default:
		return "detected-credential-" + shortFP
	}
}

func detectRegistryCredentialKeys(curl string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, re := range registryCredentialPatterns {
		matches := re.FindAllStringSubmatch(curl, -1)
		for _, m := range matches {
			if len(m) < 3 {
				continue
			}
			key := m[2]
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, key)
		}
	}
	return out
}

func sanitizeRegistryCurl(curl, modelName string) string {
	out := curl
	placeholder := "{{CREDENTIAL:" + modelName + "}}"
	for _, key := range detectRegistryCredentialKeys(curl) {
		out = strings.ReplaceAll(out, key, placeholder)
	}
	return out
}

func (s *Server) StartAdmin() {
	mux := http.NewServeMux()
	client := &http.Client{Timeout: 5 * time.Second}

	defaultOrgID := s.cfg.OrgID
	ownerEmail := strings.ToLower(strings.TrimSpace(s.cfg.OwnerEmail))
	machineID := ensureMachineID(s.cfg.UserDataDir)
	machineName, _ := os.Hostname()
	if strings.TrimSpace(machineName) == "" {
		machineName = "boanclaw-local"
	}
	ownerMatch := func(email string) bool {
		return ownerEmail != "" && strings.EqualFold(strings.TrimSpace(email), ownerEmail)
	}
	issueSession := func(w http.ResponseWriter, email, name string, roleVal roles.Role, orgID string) error {
		sess := &auth.Session{
			Sub:   email,
			Email: email,
			Name:  name,
			Role:  roleVal,
			OrgID: orgID,
		}
		token, err := s.authProv.CreateToken(sess)
		if err != nil {
			return err
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "boan_session",
			Value:    token,
			Path:     "/",
			MaxAge:   8 * 3600,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		return nil
	}

	externalBaseURL := func(r *http.Request) string {
		if s.cfg.AppBaseURL != "" {
			return strings.TrimRight(s.cfg.AppBaseURL, "/")
		}
		scheme := r.Header.Get("X-Forwarded-Proto")
		if scheme == "" {
			if r.TLS != nil {
				scheme = "https"
			} else {
				scheme = "http"
			}
		}
		host := r.Header.Get("X-Forwarded-Host")
		if host == "" {
			host = r.Host
		}
		return scheme + "://" + host
	}

	callbackURL := func(r *http.Request) string {
		if s.cfg.OAuthRedirectURL != "" {
			return s.cfg.OAuthRedirectURL
		}
		return externalBaseURL(r) + "/api/auth/callback"
	}

	redirectOrJSON := func(w http.ResponseWriter, r *http.Request, target string, payload map[string]any) {
		if target != "" {
			http.Redirect(w, r, target, http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(payload)
	}

	cors := func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return true
		}
		return false
	}

	createInputGateApproval := func(requester, orgID, reason string, req InputGateRequest) string {
		id := fmt.Sprintf("apr-%s", randomMachineID()[:12])
		args := []string{
			fmt.Sprintf("mode=%s", req.Mode),
			fmt.Sprintf("reason=%s", reason),
		}
		if trimmed := strings.TrimSpace(req.Key); trimmed != "" {
			args = append(args, fmt.Sprintf("key=%s", trimmed))
		}
		if trimmed := strings.TrimSpace(req.Text); trimmed != "" {
			preview := trimmed
			if len(preview) > 160 {
				preview = preview[:160] + "..."
			}
			args = append(args, fmt.Sprintf("text=%s", preview))
		}
		approvalsMu.Lock()
		approvalsStore = append(approvalsStore, map[string]any{
			"id":          id,
			"sessionId":   "input-gate",
			"command":     "critical-guardrail:review",
			"args":        args,
			"requester":   requester,
			"org_id":      orgID,
			"requestedAt": time.Now().UTC().Format(time.RFC3339),
			"status":      "pending",
		})
		approvalsMu.Unlock()
		return id
	}

	mountRootForOrg := func(_ string) string {
		root := strings.TrimSpace(os.Getenv("BOAN_MOUNT_ROOT"))
		if root == "" {
			home, _ := os.UserHomeDir()
			if home == "" {
				home = "/root"
			}
			root = filepath.Join(home, "Desktop", "boanclaw")
		}
		return filepath.Clean(root)
	}

	// (S1 staging dir 은 더 이상 사용 안 함 — SCP 로 GCP Windows 에 직접 전송)

	isWithinMountRoot := func(root, target string) bool {
		cleanRoot := filepath.Clean(root)
		cleanTarget := filepath.Clean(target)
		return cleanTarget == cleanRoot || strings.HasPrefix(cleanTarget, cleanRoot+string(os.PathSeparator))
	}

	resolveOrg := func(r *http.Request) string {
		if !s.authProv.Enabled() {
			return defaultOrgID
		}
		sess, err := auth.SessionFromRequest(r, s.authProv)
		if err != nil || sess.OrgID == "" {
			return defaultOrgID
		}
		return sess.OrgID
	}

	requestApprovalMessage := "사용 요청이 소유자에게 전달되었습니다. 소유자 승인 후 로그인할 수 있습니다."

	toOrgWorkstation := func(ws *userstore.Workstation) *orgserver.Workstation {
		if ws == nil {
			return nil
		}
		return &orgserver.Workstation{
			Provider:      ws.Provider,
			Platform:      ws.Platform,
			Status:        ws.Status,
			DisplayName:   ws.DisplayName,
			InstanceID:    ws.InstanceID,
			Region:        ws.Region,
			ConsoleURL:    ws.ConsoleURL,
			WebDesktopURL: ws.WebDesktopURL,
			AssignedAt:    ws.AssignedAt.Format(time.RFC3339),
		}
	}

	ensureWorkstation := func(ctx context.Context, email, orgID string) (*userstore.Workstation, error) {
		current, _ := s.users.Workstation(email)
		ws, err := s.workstations.Ensure(ctx, email, orgID, current)
		if err != nil {
			return nil, err
		}
		if ws != nil {
			if err := s.users.AssignWorkstation(email, ws); err != nil {
				return nil, err
			}
		}
		return ws, nil
	}

	warmWorkstation := func(email, orgID string) {
		email = strings.TrimSpace(strings.ToLower(email))
		if email == "" || orgID == "" {
			return
		}
		go func() {
			if _, err := ensureWorkstation(context.Background(), email, orgID); err != nil {
				log.Printf("workstation warmup failed for %s: %v", email, err)
			}
		}()
	}

	syncLocalUser := func(email, orgID, role string, status userstore.Status) {
		_, _ = s.users.Upsert(strings.TrimSpace(strings.ToLower(email)), orgID, role, status)
	}

	syncOrgUser := func(email, name, orgID, role, provider, status string) error {
		return s.orgServer.SyncUser(orgID, strings.TrimSpace(strings.ToLower(email)), name, role, provider, status, machineID, machineName)
	}

	inferBoundUser := func() string {
		var approvedUsers []string
		for _, u := range s.users.List() {
			if u == nil || u.Status != userstore.StatusApproved {
				continue
			}
			if roles.Normalize(roles.Role(u.Role)) == roles.Owner {
				continue
			}
			approvedUsers = append(approvedUsers, strings.TrimSpace(strings.ToLower(u.Email)))
		}
		if len(approvedUsers) == 1 {
			return approvedUsers[0]
		}
		return ""
	}

	readBoundUser := func() string {
		if strings.TrimSpace(s.cfg.UserDataDir) == "" {
			return inferBoundUser()
		}
		raw, err := os.ReadFile(filepath.Join(s.cfg.UserDataDir, "bound_user"))
		if err != nil {
			return inferBoundUser()
		}
		bound := strings.TrimSpace(strings.ToLower(string(raw)))
		if bound != "" {
			return bound
		}
		return inferBoundUser()
	}

	bindUserToPC := func(email string) {
		if strings.TrimSpace(s.cfg.UserDataDir) == "" {
			return
		}
		_ = os.MkdirAll(s.cfg.UserDataDir, 0700)
		_ = os.WriteFile(filepath.Join(s.cfg.UserDataDir, "bound_user"), []byte(strings.TrimSpace(strings.ToLower(email))), 0600)
	}

	if bound := inferBoundUser(); bound != "" && readBoundUser() == bound {
		bindUserToPC(bound)
	}

	deviceLockedMessage := "이 PC는 이미 다른 사용자 계정에 연결되어 있습니다. 소유자 계정은 로그인할 수 있지만, 사용자 계정은 한 PC당 1개만 사용할 수 있습니다."

	// 소유자 IP 제한: BOAN_OWNER_ALLOWED_IPS 에 등록된 IP에서만 소유자 로그인 가능.
	// 미등록 IP에서 소유자 이메일로 로그인 시 → 일반 사용자로 다운그레이드.
	ownerAllowedIPs := splitCSV(os.Getenv("BOAN_OWNER_ALLOWED_IPS"))

	isOwnerIPAllowed := func(r *http.Request) bool {
		if len(ownerAllowedIPs) == 0 {
			return true // 미설정 시 제한 없음
		}
		clientIP := r.Header.Get("X-Forwarded-For")
		if clientIP == "" {
			clientIP = r.Header.Get("X-Real-IP")
		}
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}
		// X-Forwarded-For can have multiple IPs; use the first (client)
		if idx := strings.Index(clientIP, ","); idx > 0 {
			clientIP = strings.TrimSpace(clientIP[:idx])
		}
		// Strip port from RemoteAddr
		if idx := strings.LastIndex(clientIP, ":"); idx > 0 {
			clientIP = clientIP[:idx]
		}
		for _, allowed := range ownerAllowedIPs {
			if clientIP == allowed {
				return true
			}
		}
		log.Printf("[owner-ip] blocked owner login from IP %s (allowed: %v)", clientIP, ownerAllowedIPs)
		return false
	}

	resolveLoginAccess := func(email, name, provider, wantOrgID string, r *http.Request) (roles.Role, string, bool, string, error) {
		email = strings.TrimSpace(strings.ToLower(email))
		orgID := defaultOrgID
		if wantOrgID != "" {
			orgID = wantOrgID
		}

		if ownerMatch(email) {
			// IP 검증: 등록된 IP에서만 소유자 로그인 허용
			if !isOwnerIPAllowed(r) {
				// 소유자 이메일이지만 미등록 IP → 일반 사용자로 다운그레이드
				syncLocalUser(email, orgID, string(roles.User), userstore.StatusApproved)
				return roles.User, orgID, true, "", nil
			}
			syncLocalUser(email, orgID, string(roles.Owner), userstore.StatusApproved)
			if err := syncOrgUser(email, name, orgID, string(roles.Owner), provider, "approved"); err != nil {
				return roles.User, orgID, false, "", err
			}
			return roles.Owner, orgID, true, "", nil
		}

		if bound := readBoundUser(); bound != "" && bound != email {
			return roles.User, orgID, false, deviceLockedMessage, nil
		}

		if users, err := s.orgServer.ListUsers(orgID); err == nil {
			for _, u := range users {
				if !strings.EqualFold(u.Email, email) {
					continue
				}
				role := roles.User
				if ownerMatch(email) {
					role = roles.Owner
				}
				status := userstore.StatusPending
				if u.Status == string(userstore.StatusApproved) {
					status = userstore.StatusApproved
				}
				syncLocalUser(email, orgID, string(role), status)
				if status == userstore.StatusApproved {
					bindUserToPC(email)
					return role, orgID, true, "", nil
				}
				return roles.User, orgID, false, requestApprovalMessage, nil
			}
		}

		syncLocalUser(email, orgID, string(roles.User), userstore.StatusPending)
		if err := syncOrgUser(email, name, orgID, string(roles.User), provider, "pending"); err != nil {
			return roles.User, orgID, false, "", err
		}
		return roles.User, orgID, false, requestApprovalMessage, nil
	}

	requireEdit := func(w http.ResponseWriter, r *http.Request) bool {
		if !s.authProv.Enabled() {
			return false
		}
		sess, err := auth.SessionFromRequest(r, s.authProv)
		if err != nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return true
		}
		if !roles.CanEdit(sess.Role) {
			http.Error(w, `{"error":"forbidden","role":"`+string(sess.Role)+`"}`, http.StatusForbidden)
			return true
		}
		return false
	}

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// ── G3 Wiki data: training log + stats ──
	mux.HandleFunc("/api/admin/wiki", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		entries, err := s.orgServer.GetTrainingLog(defaultOrgID)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": "training log fetch failed: " + err.Error()})
			return
		}
		// Compute stats
		total := len(entries)
		humanCount, autoCount, approveCount, rejectCount := 0, 0, 0, 0
		for _, e := range entries {
			if e["source"] == "human" {
				humanCount++
			} else {
				autoCount++
			}
			if e["decision"] == "approve" {
				approveCount++
			} else {
				rejectCount++
			}
		}
		// Also fetch wiki pages
		wikiPages, _ := s.orgServer.GetWikiPages(defaultOrgID)
		if wikiPages == nil {
			wikiPages = []map[string]any{}
		}
		wikiIndex, _ := s.orgServer.GetWikiIndex(defaultOrgID)
		json.NewEncoder(w).Encode(map[string]any{
			"entries": entries,
			"stats": map[string]int{
				"total":   total,
				"human":   humanCount,
				"auto":    autoCount,
				"approve": approveCount,
				"reject":  rejectCount,
			},
			"wiki_pages": wikiPages,
			"wiki_index": wikiIndex,
		})
	})

	// ── Wiki compile (owner only) ──
	mux.HandleFunc("/api/admin/wiki/compile", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) { return }
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if requireEdit(w, r) {
			return
		}
		if err := s.orgServer.CompileWiki(defaultOrgID); err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// ── Wiki pages (all pages with content) ──
	mux.HandleFunc("/api/admin/wiki/pages", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) { return }
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		pages, err := s.orgServer.GetWikiPages(defaultOrgID)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		if pages == nil {
			pages = []map[string]any{}
		}
		json.NewEncoder(w).Encode(pages)
	})

	// ── auto-update: version check + trigger ──
	versionFile := os.Getenv("BOAN_VERSION_FILE")
	latestVersionFile := os.Getenv("BOAN_LATEST_VERSION_FILE")
	triggerFile := os.Getenv("BOAN_UPDATE_TRIGGER_FILE")

	mux.HandleFunc("/api/admin/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		_ = r

		current := "unknown"
		if versionFile != "" {
			if b, err := os.ReadFile(versionFile); err == nil {
				current = strings.TrimSpace(string(b))
			}
		}

		latest := ""
		if latestVersionFile != "" {
			if b, err := os.ReadFile(latestVersionFile); err == nil {
				latest = strings.TrimSpace(string(b))
			}
		}

		updateAvailable := latest != "" && current != "unknown" && latest != current

		json.NewEncoder(w).Encode(map[string]any{
			"current":          current,
			"latest":           latest,
			"update_available": updateAvailable,
		})
	})

	mux.HandleFunc("/api/admin/update", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Cookie")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		// owner only
		if s.authProv.Enabled() {
			sess, err := auth.SessionFromRequest(r, s.authProv)
			if err != nil || !roles.CanEdit(sess.Role) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "owner only"})
				return
			}
		}

		if triggerFile == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "update trigger not configured"})
			return
		}
		if err := os.WriteFile(triggerFile, []byte("update"), 0644); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "trigger write failed: " + err.Error()})
			return
		}
		log.Printf("[update] update triggered via admin API")
		json.NewEncoder(w).Encode(map[string]any{"status": "updating"})
	})

	mux.HandleFunc("/api/auth/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(map[string]any{
			"sso_providers":         []map[string]any{},
			"redirect_url":          callbackURL(r),
			"allowed_email_domains": splitCSV(s.cfg.AllowedEmailDomains),
			"test_mode":             s.cfg.TestMode,
			"owner_email":           s.cfg.OwnerEmail,
		})
	})

	mux.HandleFunc("/api/auth/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		if !s.authProv.Enabled() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]any{
				"error":   "oauth_not_configured",
				"message": "BOAN_OAUTH_CLIENT_ID 와 BOAN_OAUTH_CLIENT_SECRET 환경변수를 설정하세요.",
				"setup_guide": map[string]string{
					"step1": "GCP Console → APIs & Services → Credentials → Create OAuth 2.0 Client ID",
					"step2": "Application type: Web application",
					"step3": "Authorized redirect URI: " + callbackURL(r),
					"step4": "Cloud Run 환경변수에 BOAN_OAUTH_CLIENT_ID, BOAN_OAUTH_CLIENT_SECRET 추가",
				},
			})
			return
		}
		st, err := s.authProv.CreateStateToken(&auth.OAuthState{
			RedirectURL: callbackURL(r),
			ReturnTo:    externalBaseURL(r),
			IssuedAt:    time.Now().Unix(),
		})
		if err != nil {
			http.Error(w, "state creation failed", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, s.authProv.AuthURL(st, callbackURL(r)), http.StatusFound)
	})

	mux.HandleFunc("/api/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			return
		}
		stateToken := r.URL.Query().Get("state")
		state, err := s.authProv.ParseStateToken(stateToken)
		if err != nil {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		accessToken, err := s.authProv.ExchangeCode(code, state.RedirectURL)
		if err != nil {
			http.Error(w, "token exchange failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		userInfo, err := s.authProv.GetUserInfo(accessToken)
		if err != nil {
			http.Error(w, "userinfo failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		if !s.authProv.ValidateEmailDomain(userInfo.Email) {
			http.Error(w, "forbidden: company email required", http.StatusForbidden)
			return
		}
		orgs, _ := s.authProv.FindUserOrgs(accessToken)
		if len(orgs) > 1 {
			orgListJSON, _ := json.Marshal(map[string]any{
				"orgs":         orgs,
				"access_token": accessToken,
				"user_info":    userInfo,
				"return_to":    state.ReturnTo,
			})
			encoded := base64.StdEncoding.EncodeToString(orgListJSON)
			redirectOrJSON(w, r, strings.TrimRight(state.ReturnTo, "/")+"/select-org?data="+url.QueryEscape(encoded), map[string]any{
				"status":     "select_org_required",
				"return_to":  state.ReturnTo,
				"org_count":  len(orgs),
				"user_email": userInfo.Email,
			})
			return
		}
		// Single GCP org: use it directly if available
		ssoOrgID := ""
		if len(orgs) == 1 {
			ssoOrgID = orgs[0].OrgID
		}
		role, gcpOrgID, allowed, pendingMsg, err := resolveLoginAccess(userInfo.Email, userInfo.Name, "google", ssoOrgID, r)
		if err != nil {
			http.Error(w, "org server sync failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		if !allowed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{
				"error":  pendingMsg,
				"status": "pending_approval",
				"org_id": gcpOrgID,
				"email":  userInfo.Email,
			})
			return
		}
		sess := &auth.Session{
			Sub:   userInfo.Sub,
			Email: userInfo.Email,
			Name:  userInfo.Name,
			Role:  role,
			OrgID: gcpOrgID,
		}
		token, err := s.authProv.CreateToken(sess)
		if err != nil {
			http.Error(w, "token creation failed", http.StatusInternalServerError)
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
		redirectOrJSON(w, r, state.ReturnTo+"/?login=ok", map[string]any{
			"status": "ok",
			"email":  userInfo.Email,
			"org_id": gcpOrgID,
			"role":   string(role),
		})
	})

	mux.HandleFunc("/api/auth/select-org", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body struct {
			AccessToken string `json:"access_token"`
			OrgID       string `json:"org_id"`
			Email       string `json:"email"`
			Name        string `json:"name"`
			Sub         string `json:"sub"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Validate body.OrgID against user's actual GCP orgs (prevent spoofing)
		selectedOrgID := ""
		if body.AccessToken != "" && body.OrgID != "" {
			userOrgs, _ := s.authProv.FindUserOrgs(body.AccessToken)
			for _, o := range userOrgs {
				if o.OrgID == body.OrgID {
					selectedOrgID = body.OrgID
					break
				}
			}
		}
		role, orgID, allowed, pendingMsg, err := resolveLoginAccess(body.Email, body.Name, "google", selectedOrgID, r)
		if err != nil {
			http.Error(w, "org server sync failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		if !allowed {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{
				"error":  pendingMsg,
				"status": "pending_approval",
				"org_id": orgID,
				"email":  body.Email,
			})
			return
		}
		sess := &auth.Session{
			Sub:   body.Sub,
			Email: body.Email,
			Name:  body.Name,
			Role:  role,
			OrgID: orgID,
		}
		token, _ := s.authProv.CreateToken(sess)
		http.SetCookie(w, &http.Cookie{
			Name:     "boan_session",
			Value:    token,
			Path:     "/",
			MaxAge:   8 * 3600,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"org_id":     orgID,
			"role":       string(role),
			"role_label": roles.Labels[role],
		})
	})

	mux.HandleFunc("/api/auth/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		sess, err := auth.SessionFromRequest(r, s.authProv)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]any{
				"enabled":       s.authProv.Enabled(),
				"authenticated": false,
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"enabled":       s.authProv.Enabled(),
			"authenticated": true,
			"sub":           sess.Sub,
			"email":         sess.Email,
			"name":          sess.Name,
			"role":          string(roles.Normalize(sess.Role)),
			"role_label":    roles.Labels[roles.Normalize(sess.Role)],
			"can_edit":      roles.CanEdit(roles.Normalize(sess.Role)),
			"org_id":        sess.OrgID,
		})
		if u, err := s.users.Get(sess.Email); err == nil && u.Status == userstore.StatusApproved {
			warmWorkstation(sess.Email, sess.OrgID)
		}
	})

	mux.HandleFunc("/api/openclaw/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		sess, err := auth.SessionFromRequest(r, s.authProv)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"authenticated": false})
			return
		}
		_ = sess
		json.NewEncoder(w).Encode(map[string]any{
			"url": "/openclaw/#token=" + s.cfg.OpenClawGatewayToken,
		})
	})

	mux.HandleFunc("/api/openclaw/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cfg, err := s.openClawConfig(r.Context(), "http://localhost:18081")
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(cfg)
	})

	mux.HandleFunc("/api/openclaw/v1/models", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		cfg, err := s.openClawConfig(r.Context(), "http://localhost:18081")
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"object": "list",
			"data": []map[string]any{
				{
					"id":       cfg.ModelID,
					"object":   "model",
					"created":  time.Now().Unix(),
					"owned_by": "boanclaw",
				},
			},
		})
	})

	createCredentialGateApproval := func(orgID string, keys []string, previews []string, fps []string) string {
		id := fmt.Sprintf("apr-%s", randomMachineID()[:12])
		args := make([]string, 0, len(previews))
		candidates := make([]credentialApprovalCandidate, 0, len(keys))
		for idx, p := range previews {
			role := "detected-credential"
			if idx < len(keys) && idx < len(fps) {
				role = credentialGateRoleName(keys[idx], fps[idx])
				candidates = append(candidates, credentialApprovalCandidate{
					Role:        role,
					Key:         keys[idx],
					Preview:     p,
					Fingerprint: fps[idx],
				})
			}
			args = append(args, fmt.Sprintf("credential=%s", p))
			args = append(args, fmt.Sprintf("role=%s", role))
		}
		approvalsMu.Lock()
		approvalsStore = append(approvalsStore, map[string]any{
			"id":                      id,
			"sessionId":               "credential-gate",
			"command":                 "credential-gate:register",
			"args":                    args,
			"requester":               orgID,
			"org_id":                  orgID,
			"requestedAt":             time.Now().UTC().Format(time.RFC3339),
			"status":                  "pending",
			"credential_fingerprints": fps,
		})
		if len(candidates) > 0 {
			pendingCredentialApprovals[id] = candidates
		}
		approvalsMu.Unlock()
		return id
	}

	// ── queueComputerUseCommand ──────────────────────────────────────────────
	// 브라우저 폴링 큐에 커맨드 추가. BOAN_COMPUTER_USE_URL 설정 시 외부 프록시로 위임.
	queueComputerUseCommand := func(params map[string]any, timeout time.Duration) (map[string]any, error) {
		if delegateURL := os.Getenv("BOAN_COMPUTER_USE_URL"); delegateURL != "" {
			body, _ := json.Marshal(params)
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			client := &http.Client{Transport: &http.Transport{
				Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
			}}
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, delegateURL+"/api/computer-use/execute", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			var result map[string]any
			json.NewDecoder(resp.Body).Decode(&result)
			if resp.StatusCode >= 400 {
				if errMsg, _ := result["error"].(string); errMsg != "" {
					return nil, fmt.Errorf(errMsg)
				}
				return nil, fmt.Errorf("computer-use delegate failed: %d", resp.StatusCode)
			}
			return result, nil
		}
		idBytes := make([]byte, 8)
		crand.Read(idBytes)
		id := hex.EncodeToString(idBytes)
		done := make(chan []byte, 1)
		cuQueueMu.Lock()
		cuPendingQueue = append(cuPendingQueue, &cuQueuedCmd{id: id, params: params, done: done})
		cuQueueMu.Unlock()
		select {
		case result := <-done:
			var decoded map[string]any
			if err := json.Unmarshal(result, &decoded); err != nil {
				return nil, fmt.Errorf("decode command result: %w", err)
			}
			return decoded, nil
		case <-time.After(timeout):
			cuQueueMu.Lock()
			for i, c := range cuPendingQueue {
				if c.id == id {
					cuPendingQueue = append(cuPendingQueue[:i], cuPendingQueue[i+1:]...)
					break
				}
			}
			for i, c := range cuInFlight {
				if c.id == id {
					cuInFlight = append(cuInFlight[:i], cuInFlight[i+1:]...)
					break
				}
			}
			cuQueueMu.Unlock()
			return nil, fmt.Errorf("timeout waiting for browser to execute command")
		}
	}

	writeOpenAITextResponse := func(w http.ResponseWriter, content string) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-" + hex.EncodeToString(func() []byte { b := make([]byte, 6); crand.Read(b); return b }()),
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "boan/operator",
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": content,
					},
					"finish_reason": "stop",
				},
			},
		})
	}

	parseOperatorMode := func(raw, defaultMode string) (string, string) {
		trimmed := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(strings.ToLower(trimmed), "chat "):
			return "chat", strings.TrimSpace(trimmed[5:])
		case strings.HasPrefix(trimmed, "전송 "):
			return "gcp_send", strings.TrimSpace(strings.TrimPrefix(trimmed, "전송 "))
		case strings.HasPrefix(trimmed, "실행 "):
			return "gcp_exec", strings.TrimSpace(strings.TrimPrefix(trimmed, "실행 "))
		case strings.HasPrefix(trimmed, "[gcp_send] "):
			return "gcp_send", strings.TrimSpace(strings.TrimPrefix(trimmed, "[gcp_send] "))
		case strings.HasPrefix(trimmed, "[gcp_exec] "):
			return "gcp_exec", strings.TrimSpace(strings.TrimPrefix(trimmed, "[gcp_exec] "))
		default:
			return defaultMode, trimmed
		}
	}

	// registry에서 security LLM 정보를 캐싱 (guardrail 요청에 포함)
	securityLLMURL, securityLLMModel := "", ""
	if entry, err := s.loadSelectedRegistryLLM(context.Background()); err == nil && entry != nil {
		securityLLMURL = entry.Endpoint
		securityLLMModel = entry.Name
		if entry.CurlTemplate != "" {
			_, ep, _, _ := parseCurlTemplate(entry.CurlTemplate)
			if ep != "" {
				securityLLMURL = ep
			}
		}
	}

	runGCPSend := func(ctx context.Context, requester, orgID, text string) (string, error) {
		// 사용자 access_level 조회 (default "ask")
		userAccessLevel := "ask"
		if requester != "" && !strings.Contains(requester, "openclaw-control-ui") {
			if u, err := s.users.Get(requester); err == nil && u != nil && u.AccessLevel != "" {
				userAccessLevel = string(u.AccessLevel)
			}
		}
		// Fetch G1 patterns from policy
		var g1Patterns []G1PatternRule
		if rules, _ := s.guardrail.GetGuardrailRules(ctx, orgID); rules != nil {
			for _, r := range rules.G1Patterns {
				g1Patterns = append(g1Patterns, G1PatternRule{Pattern: r.Pattern, Mode: r.Mode})
			}
		}
		req := InputGateRequest{
			Mode: "text", Text: text, SrcLevel: 3, DestLevel: 1,
			Flow:       "openclaw-chat-to-remote-workstation",
			UserEmail:  requester, AccessLevel: userAccessLevel,
			LLMURL:     securityLLMURL, LLMModel: securityLLMModel,
			G1Patterns: g1Patterns,
		}
		resp := evaluateInputGateWithLocal(ctx, s.dlpEng, s.guardrail, s.evaluateGuardrailLocal, orgID, req,
			func(reason string, r InputGateRequest) string {
				return createInputGateApproval(requester, orgID, reason, r)
			},
		)
		if resp.Action == "credential_required" && text != "" {
			gateResult := s.applyCredentialGate(ctx, orgID, text, func(keys []string, previews []string, fps []string) string {
				return createCredentialGateApproval(orgID, keys, previews, fps)
			})
			resp = InputGateResponse{Allowed: true, Action: "allow", Tier: "G1+credential", NormalizedText: gateResult.Prompt, Reason: "credential substituted", ApprovalID: gateResult.ApprovalID}
			if gateResult.HITLRequired {
				resp.Reason = "credential detected; unknown values redacted, HITL created"
			}
		}
		// Observability trace — tier 와 reason 포함
		trSummary := text
		if len(trSummary) > 200 {
			trSummary = trSummary[:200] + "..."
		}
		addTrace(traceEntry{
			Type: "guardrail", Direction: "outbound", Source: requester, Target: "gcp",
			Summary: trSummary, Decision: resp.Action, Gate: resp.Tier,
			Meta: map[string]any{
				"flow":         req.Flow,
				"src_level":    req.SrcLevel,
				"dest_level":   req.DestLevel,
				"tier":         resp.Tier,
				"reason":       resp.Reason,
				"access_level": userAccessLevel,
			},
		})
		if !resp.Allowed {
			if resp.Action == "hitl_required" && resp.ApprovalID != "" {
				return fmt.Sprintf("입력이 보류되었습니다. 관리자 승인 대기 중입니다. approval=%s", resp.ApprovalID), nil
			}
			return "", fmt.Errorf("가드레일에 통과되지 못하였습니다 — [%s] %s", resp.Tier, firstNonEmptyString(resp.Reason, "input blocked"))
		}
		// 실제 타이핑은 클라이언트(브라우저)가 직접 injectTextToRemote로 처리.
		// 여기서는 가드레일 통과 결과만 반환.
		return "입력이 검사를 통과했고 원격 화면에 전달되었습니다.", nil
	}

	runComputerUseAgent := func(ctx context.Context, orgID, prompt string, sendEvent func(map[string]any)) (string, int, error) {
		send := func(evt map[string]any) {
			if sendEvent != nil {
				sendEvent(evt)
			}
		}
		visionEntry, visionErr := s.loadSecurityLMM(ctx)
		if visionErr != nil {
			return "", 0, fmt.Errorf("보안 LMM이 등록되지 않았습니다: %w", visionErr)
		}
		log.Printf("[computer-use/agent] vision LMM=%s", visionEntry.Name)
		const maxSteps = 10
		executed := 0
		// visionPromptTemplate: %d=width, %d=height, %s=objective, %d=width, %d=height
		visionPromptTemplate := "This image IS the screenshot of the current display of the computer (resolution: %dx%d pixels). " +
			"It has already been automatically captured and sent to the user — you do NOT need to press PrtScn or any screenshot key.\n" +
			"The objective is: %s\n" +
			"Describe what is visible on screen. For each UI element (window, button, text field), " +
			"estimate its center position as pixel coordinates (x, y) in the full %dx%d resolution.\n" +
			"IMPORTANT: If the objective is to take/show/capture/send a screenshot, it is ALREADY COMPLETE — the image above IS the screenshot.\n" +
			"End your response with exactly one of these two lines:\n" +
			"OBJECTIVE: COMPLETE\n" +
			"OBJECTIVE: INCOMPLETE\n" +
			"If INCOMPLETE, describe the single next action: [click|type|press key] at approximately (x, y) in order to [expected result]."
		// actionSystemPromptFmt: %d=width, %d=height
		actionSystemPromptFmt := "You control a GCP Windows workstation via computer-use.\n" +
			"The screen resolution is %dx%d pixels.\n" +
			"You will be given a description of the current screen and the next step to take.\n" +
			"Respond with ONLY a JSON array of actions — no explanation, no markdown fences.\n" +
			"To indicate the task is complete, respond with: [{\"action\":\"stop\"}]\n" +
			"Available actions:\n" +
			`{"action":"screenshot"}` + " – capture current screen (returns image; use this to see the screen)\n" +
			`{"action":"type","text":"..."}` + " – type text\n" +
			`{"action":"key","name":"..."}` + " – press key: Return, Tab, Escape, BackSpace, ctrl+s, ctrl+a, ctrl+c, ctrl+v, ctrl+z (WARNING: do NOT use alt+F4)\n" +
			`{"action":"click","x":N,"y":N}` + " – left click at screen coords (use actual pixel coords, not percentages)\n" +
			`{"action":"double_click","x":N,"y":N}` + " – double click\n" +
			`{"action":"right_click","x":N,"y":N}` + " – right click\n" +
			`{"action":"scroll","x":N,"y":N,"direction":"down","amount":3}` + " – scroll\n" +
			`{"action":"stop"}` + " – task complete\n\n" +
			"NOTE: A screenshot is already taken automatically at the start of each step. Do NOT press PrtScn or PrintScreen keys to take a screenshot.\n" +
			`Example: [{"action":"click","x":100,"y":200},{"action":"stop"}]`
		for step := 0; step < maxSteps; step++ {
			send(map[string]any{"type": "status", "text": fmt.Sprintf("화면 캡처 중... (스텝 %d)", step+1)})
			ssResult, ssErr := queueComputerUseCommand(map[string]any{"action": "screenshot"}, 45*time.Second)
			if ssErr != nil {
				return "", executed, fmt.Errorf("스크린샷 실패: %w", ssErr)
			}
			screenshotB64, _ := ssResult["image"].(string)
			if screenshotB64 == "" {
				screenshotB64, _ = ssResult["data"].(string)
			}
			if screenshotB64 == "" {
				return "", executed, fmt.Errorf("스크린샷 데이터 없음")
			}
			send(map[string]any{"type": "screenshot", "data": screenshotB64, "label": fmt.Sprintf("스텝 %d 화면", step+1)})

			// 스크린샷 해상도 추출 (좌표 정확도 향상)
			scrW, scrH := getImageDimensions(screenshotB64)
			log.Printf("[computer-use/agent] step=%d screen resolution=%dx%d", step, scrW, scrH)

			send(map[string]any{"type": "status", "text": "Vision LMM이 화면을 분석 중..."})
			visionPrompt := fmt.Sprintf(visionPromptTemplate, scrW, scrH, prompt, scrW, scrH)
			thought, vErr := s.forwardVisionLLM(ctx, visionEntry, screenshotB64, visionPrompt)
			if vErr != nil {
				return "", executed, fmt.Errorf("Vision LMM 오류: %w", vErr)
			}
			send(map[string]any{"type": "thinking", "text": thought})
			lowerThought := strings.ToLower(thought)
			isComplete := strings.Contains(lowerThought, "objective: complete") &&
				!strings.Contains(lowerThought, "objective: incomplete") &&
				!strings.Contains(lowerThought, "not complete")
			if isComplete {
				return thought, executed, nil
			}
			send(map[string]any{"type": "status", "text": "Action LLM이 다음 동작을 결정 중..."})
			actionSystemPrompt := fmt.Sprintf(actionSystemPromptFmt, scrW, scrH)
			actionPrompt := actionSystemPrompt + "\n\nVision analysis:\n" + thought
			actionResp, aErr := s.forwardSelectedLLM(ctx, orgID, actionPrompt, map[string]any{"max_tokens": 512})
			if aErr != nil {
				return "", executed, fmt.Errorf("Action LLM 오류: %w", aErr)
			}
			actionText := ""
			if rawChoices, _ := json.Marshal(actionResp["choices"]); len(rawChoices) > 0 {
				var choices []struct {
					Message struct{ Content string `json:"content"` } `json:"message"`
				}
				if json.Unmarshal(rawChoices, &choices) == nil && len(choices) > 0 {
					actionText = choices[0].Message.Content
				}
			}
			start := strings.Index(actionText, "[")
			end := strings.LastIndex(actionText, "]")
			if start < 0 || end <= start {
				break
			}
			var actions []map[string]any
			if err := json.Unmarshal([]byte(actionText[start:end+1]), &actions); err != nil {
				return "", executed, fmt.Errorf("액션 파싱 실패: %s", actionText)
			}
			stopped := false
			for i, action := range actions {
				if action["action"] == "stop" {
					stopped = true
					break
				}
				actionJSON, _ := json.Marshal(action)
				log.Printf("[computer-use/agent] step=%d action[%d]: %s", step, i, actionJSON)
				send(map[string]any{"type": "action", "index": executed, "action": action})
				result, err := queueComputerUseCommand(action, 45*time.Second)
				if err != nil {
					send(map[string]any{"type": "action_result", "index": executed, "error": err.Error()})
					log.Printf("[computer-use/agent] step=%d action[%d] ERROR: %v", step, i, err)
					return "", executed, err
				}
				resultJSON, _ := json.Marshal(result)
				log.Printf("[computer-use/agent] step=%d action[%d] result: %s", step, i, resultJSON)
				send(map[string]any{"type": "action_result", "index": executed, "result": result})
				executed++
			}
			if stopped {
				break
			}
		}
		return fmt.Sprintf("[BoanClaw 실행 완료] %s → %d개 액션 완료", prompt, executed), executed, nil
	}

	dispatchOperatorAction := func(ctx context.Context, requester, orgID, mode, payload string, sendEvent func(map[string]any)) (string, error) {
		switch mode {
		case "chat":
			runID, err := openClawChatSend(payload, hex.EncodeToString(func() []byte { b := make([]byte, 8); crand.Read(b); return b }()))
			if err != nil {
				return "", err
			}
			if strings.TrimSpace(runID) == "" {
				return "BoanClaw 채팅으로 전달했습니다.", nil
			}
			return "BoanClaw 채팅으로 전달했습니다. runId=" + runID, nil
		case "gcp_send":
			return runGCPSend(ctx, requester, orgID, payload)
		case "gcp_exec":
			resultText, executed, err := runComputerUseAgent(ctx, orgID, payload, sendEvent)
			if err != nil {
				return "", err
			}
			if executed > 0 && !strings.Contains(resultText, "액션") {
				resultText = fmt.Sprintf("%s\n\n실행 완료: %d개 액션", resultText, executed)
			}
			return resultText, nil
		default:
			return "", fmt.Errorf("unsupported mode: %s", mode)
		}
	}

	mux.HandleFunc("/api/openclaw/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		orgID := resolveOrg(r)
		sess, _ := auth.SessionFromRequest(r, s.authProv)
		sender := orgID
		if sess != nil { sender = sess.Email }
		prompt := extractPromptFromMessages(body["messages"])
		mode, payload := parseOperatorMode(prompt, "chat")
		log.Printf("[openclaw/v1] mode=%s payload=%.80q org=%s user=%s", mode, payload, orgID, sender)

		// G1/G2/G3 가드레일: OpenClaw 채팅도 가드레일 적용
		// registry에서 security LLM 정보 가져오기
		var secLLMURL, secLLMModel string
		if entry, err := s.loadSelectedRegistryLLM(r.Context()); err == nil && entry != nil {
			secLLMModel = entry.Name
			if entry.CurlTemplate != "" {
				if _, ep, _, _ := parseCurlTemplate(entry.CurlTemplate); ep != "" {
					secLLMURL = ep
				}
			}
			if secLLMURL == "" { secLLMURL = entry.Endpoint }
		}
		// 사용자 access_level 조회
		userAccessLevel := "ask"
		if sess != nil {
			if u, err := s.users.Get(sess.Email); err == nil && u != nil {
				if u.AccessLevel != "" { userAccessLevel = string(u.AccessLevel) }
			}
		}

		if mode == "chat" && payload != "" {
			gateResp := evaluateInputGateWithLocal(r.Context(), s.dlpEng, s.guardrail, s.evaluateGuardrailLocal, orgID, InputGateRequest{
				Mode: "text", Text: payload, SrcLevel: 3, DestLevel: 1,
				Flow: "openclaw-chat-direct",
				UserEmail: sender, AccessLevel: userAccessLevel,
				LLMURL: secLLMURL, LLMModel: secLLMModel,
			}, func(reason string, req InputGateRequest) string {
				return createInputGateApproval(sender, orgID, reason, req)
			})
			if !gateResp.Allowed {
				log.Printf("[openclaw/v1] guardrail blocked tier=%s action=%s reason=%q", gateResp.Tier, gateResp.Action, gateResp.Reason)
				addTrace(traceEntry{
					Type: "guardrail", Direction: "inbound", Source: sender, Target: "llm",
					Summary: payload, Decision: gateResp.Action, Gate: gateResp.Tier,
				})
				writeOpenAITextResponse(w, formatGuardrailBlockMessage(gateResp, payload))
				return
			}
		}

		summary := payload
		if len(summary) > 200 { summary = summary[:200] + "..." }
		addTrace(traceEntry{
			Type: "chat", Direction: "inbound", Source: sender, Target: "llm",
			Summary: summary, Decision: "allow", Gate: "G1",
		})

		if mode != "chat" {
			isStream, _ := body["stream"].(bool)
			buildResp := func(content string) map[string]any {
				return map[string]any{
					"id":      "chatcmpl-" + hex.EncodeToString(func() []byte { b := make([]byte, 6); crand.Read(b); return b }()),
					"object":  "chat.completion",
					"created": time.Now().Unix(),
					"model":   "boan/operator",
					"choices": []map[string]any{
						{"index": 0, "message": map[string]any{"role": "assistant", "content": content}, "finish_reason": "stop"},
					},
				}
			}
			writeResp := func(content string) {
				if isStream {
					writeOpenAIStream(w, buildResp(content))
				} else {
					writeOpenAITextResponse(w, content)
				}
			}

			var collectedScreenshots []string
			var collectMu sync.Mutex
			var sendEvt func(map[string]any)
			if mode == "gcp_exec" {
				sendEvt = func(evt map[string]any) {
					if evt["type"] == "screenshot" {
						if data, ok := evt["data"].(string); ok && data != "" {
							collectMu.Lock()
							collectedScreenshots = append(collectedScreenshots, data)
							collectMu.Unlock()
						}
					}
				}
			}
			resultText, err := dispatchOperatorAction(r.Context(), "openclaw-control-ui", orgID, mode, payload, sendEvt)
			if err != nil {
				if !isStream {
					w.WriteHeader(http.StatusBadGateway)
				}
				writeResp(err.Error())
				return
			}
			if len(collectedScreenshots) > 0 {
				contentParts := []map[string]any{{"type": "text", "text": resultText}}
				for _, ss := range collectedScreenshots {
					contentParts = append(contentParts, map[string]any{
						"type":      "image_url",
						"image_url": map[string]any{"url": "data:image/png;base64," + ss},
					})
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":      "chatcmpl-" + hex.EncodeToString(func() []byte { b := make([]byte, 6); crand.Read(b); return b }()),
					"object":  "chat.completion",
					"created": time.Now().Unix(),
					"model":   "boan/operator",
					"choices": []map[string]any{
						{"index": 0, "message": map[string]any{"role": "assistant", "content": contentParts}, "finish_reason": "stop"},
					},
				})
				return
			}
			writeResp(resultText)
			return
		}

		// Apply credential gate: replace registered creds, redact unknown, HITL for new.
		gateResult := s.applyCredentialGate(r.Context(), orgID, prompt, func(keys []string, previews []string, fps []string) string {
			return createCredentialGateApproval(orgID, keys, previews, fps)
		})

		resp, err := s.forwardSelectedLLM(r.Context(), orgID, gateResult.Prompt, body)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		if gateResult.HITLRequired && gateResult.ApprovalID != "" {
			w.Header().Set("X-Boan-Credential-HITL", gateResult.ApprovalID)
		}
		if stream, _ := body["stream"].(bool); stream {
			writeOpenAIStream(w, resp)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// POST /api/workstation/repair — 현재 세션 사용자의 워크스테이션 RDP 비밀번호를 강제 갱신.
	// VM startup script 로 새 비밀번호 push → 재부팅 → boanclaw 에 새 자격 저장.
	// Guacamole 가 RDP "invalid credentials" 로 실패할 때 사용자가 수동 호출.
	mux.HandleFunc("/api/workstation/repair", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		sess, err := auth.SessionFromRequest(r, s.authProv)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"error": "unauthenticated"})
			return
		}
		current, _ := s.users.Workstation(sess.Email)
		if current == nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{"error": "no workstation provisioned"})
			return
		}
		repaired, repErr := s.workstations.RepairCredentials(r.Context(), sess.Email, sess.OrgID, current)
		if repErr != nil {
			log.Printf("workstation manual repair failed for %s: %v", sess.Email, repErr)
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{"error": repErr.Error()})
			return
		}
		if repaired != nil {
			_ = s.users.AssignWorkstation(sess.Email, repaired)
		}
		log.Printf("workstation repaired for %s — VM restart in progress", sess.Email)
		json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"hint":   "VM 비밀번호 재설정 + 재부팅 중입니다. 1-2분 후 Personal Computer 페이지를 새로고침하세요.",
			"email":  sess.Email,
		})
	})

	mux.HandleFunc("/api/workstation/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		sess, err := auth.SessionFromRequest(r, s.authProv)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"authenticated": false})
			return
		}
		ws, err := s.users.Workstation(sess.Email)
		if err != nil && err != userstore.ErrNotFound {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]any{"error": "failed to load workstation state"})
			return
		}
		if u, getErr := s.users.Get(sess.Email); getErr == nil && u.Status == userstore.StatusApproved {
			provisioned, provisionErr := ensureWorkstation(r.Context(), sess.Email, sess.OrgID)
			if provisionErr != nil {
				log.Printf("workstation ensure failed for %s: %v", sess.Email, provisionErr)
			} else {
				ws = provisioned
			}
		}
		if ws == nil {
			json.NewEncoder(w).Encode(map[string]any{
				"email":           sess.Email,
				"org_id":          sess.OrgID,
				"provider":        "",
				"platform":        "",
				"status":          "unprovisioned",
				"display_name":    "",
				"instance_id":     "",
				"region":          "",
				"console_url":     "",
				"web_desktop_url": "",
				"assigned_at":     "",
			})
			return
		}
		if s.guac != nil {
			drivePath := userRDPTransferDir(s.cfg.RDPTransferRoot, sess.Email)
			_ = ensureRDPTransferDir(drivePath)
			if remoteURL, remoteErr := s.guac.EnsureSessionURL(r.Context(), ws, drivePath); remoteErr == nil && remoteURL != "" {
				ws.WebDesktopURL = remoteURL
				_ = s.users.AssignWorkstation(sess.Email, ws)
			} else if remoteErr != nil {
				log.Printf("guacamole session url failed for %s: %v", sess.Email, remoteErr)
				if strings.Contains(strings.ToLower(remoteErr.Error()), "invalid credentials") {
					if repaired, repairErr := s.workstations.RepairCredentials(r.Context(), sess.Email, sess.OrgID, ws); repairErr != nil {
						log.Printf("workstation credential repair failed for %s: %v", sess.Email, repairErr)
					} else if repaired != nil {
						ws = repaired
						_ = s.users.AssignWorkstation(sess.Email, ws)
					}
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]any{
			"email":           sess.Email,
			"org_id":          sess.OrgID,
			"provider":        ws.Provider,
			"platform":        ws.Platform,
			"status":          ws.Status,
			"display_name":    ws.DisplayName,
			"instance_id":     ws.InstanceID,
			"region":          ws.Region,
			"console_url":     ws.ConsoleURL,
			"web_desktop_url": ws.WebDesktopURL,
			"assigned_at":     ws.AssignedAt,
		})
	})

	mux.HandleFunc("/api/input-gate/evaluate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		sess, err := auth.SessionFromRequest(r, s.authProv)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"authenticated": false})
			return
		}

		var body InputGateRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{
				"allowed": false,
				"action":  "block",
				"reason":  "invalid payload",
			})
			return
		}

		// 세션 기준으로 user_email/access_level 주입 (클라이언트가 이미 값 보냈어도 덮어씀 — 신뢰할 수 없음)
		body.UserEmail = sess.Email
		body.AccessLevel = "ask"
		if u, err := s.users.Get(sess.Email); err == nil && u != nil && u.AccessLevel != "" {
			body.AccessLevel = string(u.AccessLevel)
		}
		// G1 patterns 는 서버가 권위 있음 (클라이언트 body 덮어씀)
		if rules, _ := s.guardrail.GetGuardrailRules(r.Context(), sess.OrgID); rules != nil {
			body.G1Patterns = make([]G1PatternRule, 0, len(rules.G1Patterns))
			for _, r := range rules.G1Patterns {
				body.G1Patterns = append(body.G1Patterns, G1PatternRule{Pattern: r.Pattern, Mode: r.Mode})
			}
		}

		resp := evaluateInputGateWithLocal(
			r.Context(),
			s.dlpEng,
			s.guardrail,
			s.evaluateGuardrailLocal,
			sess.OrgID,
			body,
			func(reason string, req InputGateRequest) string {
				return createInputGateApproval(sess.Email, sess.OrgID, reason, req)
			},
		)
		// Credential-like input: substitute registered credentials with
		// {{CREDENTIAL:name}}, redact unknowns, then allow through.
		if resp.Action == "credential_required" && body.Text != "" {
			gateResult := s.applyCredentialGate(r.Context(), sess.OrgID, body.Text, func(keys []string, previews []string, fps []string) string {
				return createCredentialGateApproval(sess.OrgID, keys, previews, fps)
			})
			resp = InputGateResponse{
				Allowed:        true,
				Action:         "allow",
				NormalizedText: gateResult.Prompt,
				Reason:         "credential substituted",
			}
			if gateResult.HITLRequired {
				resp.Reason = "credential detected; unknown values redacted, HITL created"
				resp.ApprovalID = gateResult.ApprovalID
			}
		}
		if s.audit != nil {
			reason := resp.Reason
			if reason == "" {
				reason = body.Flow
			}
			s.audit.Log(r.Context(), audit.Event{
				Action:  "observe:input-gate",
				SLevel:  body.SrcLevel,
				Host:    fmt.Sprintf("dest_level=%d", body.DestLevel),
				User:    sess.Email,
				Reason:  fmt.Sprintf("mode=%s action=%s flow=%s %s", body.Mode, resp.Action, body.Flow, reason),
				Tool:    "input-gate",
				Method:  "POST",
				BodyHash: audit.HashBody([]byte(body.Text + "|" + body.Key)),
			})
			// observability trace — tier 와 reason 포함
			trSummary := body.Text
			if trSummary == "" { trSummary = body.Key }
			if len(trSummary) > 200 { trSummary = trSummary[:200] + "..." }
			addTrace(traceEntry{
				Type: "guardrail", Direction: "outbound", Source: sess.Email, Target: "gcp",
				Summary: trSummary, Decision: resp.Action, Gate: resp.Tier,
				Meta: map[string]any{
					"flow":         body.Flow,
					"mode":         body.Mode,
					"src_level":    body.SrcLevel,
					"dest_level":   body.DestLevel,
					"tier":         resp.Tier,
					"reason":       resp.Reason,
					"access_level": body.AccessLevel,
				},
			})
		}
		if !resp.Allowed {
			log.Printf("input gate blocked user=%s org=%s mode=%s key=%s reason=%s", sess.Email, sess.OrgID, body.Mode, body.Key, resp.Reason)
		}
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/api/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:   "boan_session",
			Value:  "",
			Path:   "/",
			MaxAge: -1,
		})
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "logged_out"})
	})

	mux.HandleFunc("/api/auth/dev-login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		var roleVal roles.Role
		var orgID string

		if u, err := s.users.Authenticate(body.Email, body.Password); err == nil {
			roleVal = roles.Normalize(roles.Role(u.Role))
			orgID = u.OrgID
			if orgID == "" {
				orgID = defaultOrgID
			}
		} else if err == userstore.ErrPending {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "승인 대기 중입니다. 관리자 승인 후 로그인할 수 있습니다."})
			return
		} else if err == userstore.ErrNotFound || err == userstore.ErrBadPass {
			if body.Password != s.cfg.AdminPassword {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "이메일 또는 비밀번호가 올바르지 않습니다."})
				return
			}
			roleVal = roles.User
			if ownerMatch(body.Email) {
				roleVal = roles.Owner
			}
			orgID = defaultOrgID
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "로그인 실패"})
			return
		}

		if err := issueSession(w, body.Email, body.Email, roleVal, orgID); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "세션 생성 실패"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"role":       string(roleVal),
			"role_label": roles.Labels[roleVal],
			"org_id":     orgID,
		})
		warmWorkstation(body.Email, orgID)
	})

	mux.HandleFunc("/api/auth/send-otp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		var body struct {
			Email string `json:"email"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Email == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "이메일을 입력해주세요."})
			return
		}
		if !s.authProv.ValidateEmailDomain(body.Email) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "허용된 회사 이메일만 사용할 수 있습니다."})
			return
		}
		// TEST 모드 — 모든 사용자가 OTP 없이 바로 로그인됨.
		// 이전에는 owner 만 우회했지만, 다중 사용자 시나리오 (예: dowoo.baik 으로 로그인해서
		// 가드레일/whitelist 검증) 를 빠르게 돌리기 위해 모든 등록된 사용자도 같이 우회.
		// production 환경(s.cfg.TestMode == false)에서는 이 분기 자체가 실행 안 됨.
		if s.cfg.TestMode {
			isOwner := ownerMatch(body.Email)
			loginType := "test_user"
			if isOwner {
				loginType = "test_owner"
			}
			roleVal, orgID, allowed, pendingMsg, err := resolveLoginAccess(body.Email, body.Email, loginType, "", r)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				json.NewEncoder(w).Encode(map[string]string{"error": "조직 서버 저장 실패: " + err.Error()})
				return
			}
			if !allowed {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": pendingMsg})
				return
			}
			if err := issueSession(w, body.Email, body.Email, roleVal, orgID); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "세션 생성 실패"})
				return
			}
			warmWorkstation(body.Email, orgID)
			hintMsg := "TEST 모드: OTP 없이 바로 로그인됩니다."
			if isOwner {
				hintMsg = "TEST 모드 소유자 계정은 OTP 없이 바로 로그인됩니다."
			}
			json.NewEncoder(w).Encode(map[string]any{
				"status":      "ok",
				"test_mode":   true,
				"bypass_otp":  true,
				"role":        string(roleVal),
				"role_label":  roles.Labels[roleVal],
				"org_id":      orgID,
				"hint":        hintMsg,
			})
			return
		}

		if _, err := s.otpStore.Generate(body.Email); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "코드 생성 실패"})
			return
		}

		smtpConfigured := s.cfg.SMTPHost != ""
		json.NewEncoder(w).Encode(map[string]any{
			"status":           "sent",
			"email_configured": smtpConfigured,
			"hint":             "이메일로 코드를 전송했습니다. 메일이 보이지 않으면 스팸함을 확인하세요.",
		})
	})

	mux.HandleFunc("/api/auth/verify-otp", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		var body struct {
			Email string `json:"email"`
			Code  string `json:"code"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		if !s.authProv.ValidateEmailDomain(body.Email) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "허용된 회사 이메일만 사용할 수 있습니다."})
			return
		}

		if !s.otpStore.Verify(body.Email, body.Code) {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{"error": "코드가 올바르지 않거나 만료되었습니다."})
			return
		}

		roleVal := roles.User
		orgID := defaultOrgID

		roleVal = roles.User
		roleVal, orgID, allowed, pendingMsg, err := resolveLoginAccess(body.Email, body.Email, "email_otp", "", r)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": "조직 서버 저장 실패: " + err.Error()})
			return
		}
		if !allowed {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": pendingMsg})
			return
		}

		if err := issueSession(w, body.Email, body.Email, roleVal, orgID); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "세션 생성 실패"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"role":       string(roleVal),
			"role_label": roles.Labels[roleVal],
			"org_id":     orgID,
		})
	})

	mux.HandleFunc("/api/auth/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			OrgID    string `json:"org_id"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		if body.Email == "" || body.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "이메일과 비밀번호를 입력해주세요."})
			return
		}
		if !s.authProv.ValidateEmailDomain(body.Email) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "허용된 회사 이메일만 사용할 수 있습니다."})
			return
		}
		if len(body.Password) < 8 {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "비밀번호는 8자 이상이어야 합니다."})
			return
		}

		// org_id is always server-determined. User input ignored for security.
		orgID := defaultOrgID

		role := string(roles.User)
		status := userstore.StatusPending
		if ownerMatch(body.Email) {
			role = string(roles.Owner)
			status = userstore.StatusApproved
		}

		u, err := s.users.Register(body.Email, body.Password, orgID, role, status)
		if err == userstore.ErrExists {
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "이미 등록된 이메일입니다."})
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "회원가입 실패: " + err.Error()})
			return
		}
		if err := s.orgServer.RegisterUserWithState(orgID, body.Email, body.Password, role, string(status), machineID, machineName); err != nil {
			_ = s.users.Delete(body.Email)
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": "조직 서버 저장 실패: " + err.Error()})
			return
		}

		json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"role":    u.Role,
			"org_id":  u.OrgID,
			"pending": u.Status == "pending",
		})
	})

	mux.HandleFunc("/api/admin/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Cookie")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method == http.MethodGet {
			allUsers := s.users.List()
			// Merge users from GCP org server (central source of truth)
			var adminOrgID string
			if sess, err := auth.SessionFromRequest(r, s.authProv); err == nil {
				adminOrgID = sess.OrgID
			}
			orgID := adminOrgID
			if orgID == "" {
				orgID = defaultOrgID
			}
			if remoteUsers, err := s.orgServer.ListUsers(orgID); err == nil {
				seen := make(map[string]bool)
				for _, u := range allUsers {
					seen[strings.ToLower(u.Email)] = true
				}
				for _, ru := range remoteUsers {
					if seen[strings.ToLower(ru.Email)] {
						continue
					}
					// Remote user not in local store — add it
					status := userstore.StatusPending
					if ru.Status == "approved" {
						status = userstore.StatusApproved
					}
					allUsers = append(allUsers, &userstore.User{
						Email:     ru.Email,
						Role:      ru.Role,
						OrgID:     orgID,
						Status:    status,
						CreatedAt: time.Now(),
					})
				}
			}
			// Filter by admin's org
			list := allUsers
			if adminOrgID != "" {
				list = nil
				for _, u := range allUsers {
					if u.OrgID == adminOrgID {
						list = append(list, u)
					}
				}
			}
			type userView struct {
				Email             string `json:"email"`
				Role              string `json:"role"`
				OrgID             string `json:"org_id"`
				Status            string `json:"status"`
				AccessLevel       string `json:"access_level"`
				CreatedAt         string `json:"created_at"`
				WorkstationStatus string `json:"workstation_status,omitempty"`
				InstanceID        string `json:"instance_id,omitempty"`
			}
			out := make([]userView, 0, len(list))
			for _, u := range list {
				accessLevel := string(u.AccessLevel)
				if accessLevel == "" {
					accessLevel = "ask" // 기존 사용자 기본값
				}
				out = append(out, userView{
					Email: u.Email,
					Role: func() string {
						if ownerMatch(u.Email) {
							return string(roles.Owner)
						}
						return string(roles.User)
					}(),
					OrgID:       u.OrgID,
					Status:      string(u.Status),
					AccessLevel: accessLevel,
					CreatedAt:   u.CreatedAt.Format("2006-01-02 15:04"),
					WorkstationStatus: func() string {
						if u.Workstation == nil {
							return ""
						}
						return u.Workstation.Status
					}(),
					InstanceID: func() string {
						if u.Workstation == nil {
							return ""
						}
						return u.Workstation.InstanceID
					}(),
				})
			}
			json.NewEncoder(w).Encode(out)
			return
		}

		if r.Method == http.MethodPatch {
			var body struct {
				Email       string `json:"email"`
				Role        string `json:"role"`
				Action      string `json:"action"`
				AccessLevel string `json:"access_level"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			// 소유자: access_level 변경은 허용, role/action 변경은 차단
			if ownerMatch(body.Email) && (body.Role != "" || body.Action != "") {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "고정 소유자의 역할/상태는 변경할 수 없습니다."})
				return
			}
			if strings.TrimSpace(body.Role) == string(roles.Owner) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "소유자 권한은 고정 소유자에게만 부여할 수 있습니다."})
				return
			}
			if body.Action == "approve" {
				// User might only exist on GCP org server (registered on another deployment).
				// Sync to local store first if not found.
				if _, err := s.users.Get(body.Email); err != nil {
					orgID := defaultOrgID
					s.users.Register(body.Email, "", orgID, string(roles.User), userstore.StatusPending)
				}
				if err := s.users.Approve(body.Email); err != nil {
					w.WriteHeader(http.StatusNotFound)
					json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
				// Sync approved status to GCP org server
				if err := s.orgServer.RegisterUserWithState(defaultOrgID, body.Email, "", string(roles.User), "approved", "", ""); err != nil {
					log.Printf("[approve] org server sync failed for %s: %v", body.Email, err)
				}
				if _, err := ensureWorkstation(r.Context(), body.Email, defaultOrgID); err != nil {
					w.WriteHeader(http.StatusBadGateway)
					json.NewEncoder(w).Encode(map[string]string{"error": "개인 작업 컴퓨터 생성 실패: " + err.Error()})
					return
				}
			}
			if body.Role != "" {
				if err := s.users.SetRole(body.Email, body.Role); err != nil {
					if err == userstore.ErrInvalidRole {
						w.WriteHeader(http.StatusBadRequest)
						json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
						return
					}
					w.WriteHeader(http.StatusNotFound)
					json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
			}
			if body.AccessLevel != "" {
				if !userstore.ValidAccessLevel(body.AccessLevel) {
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{"error": "유효하지 않은 권한 레벨: " + body.AccessLevel})
					return
				}
				if err := s.users.SetAccessLevel(body.Email, userstore.AccessLevel(body.AccessLevel)); err != nil {
					w.WriteHeader(http.StatusNotFound)
					json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
			}
			role := strings.TrimSpace(body.Role)
			if role == "" {
				if u, err := s.users.Get(body.Email); err == nil {
					role = u.Role
				}
			}
			status := ""
			if body.Action == "approve" {
				status = string(userstore.StatusApproved)
			}
			var workstation *orgserver.Workstation
			if body.Action == "approve" {
				if ws, err := s.users.Workstation(body.Email); err == nil && ws != nil {
					workstation = toOrgWorkstation(ws)
				}
			}
			if err := s.orgServer.UpdateUser(defaultOrgID, body.Email, role, status, body.AccessLevel, workstation, machineID, machineName); err != nil {
				w.WriteHeader(http.StatusBadGateway)
				json.NewEncoder(w).Encode(map[string]string{"error": "조직 서버 반영 실패: " + err.Error()})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}

		if r.Method == http.MethodDelete {
			var body struct {
				Email string `json:"email"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if ownerMatch(body.Email) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "고정 소유자는 삭제할 수 없습니다."})
				return
			}
			// 1) GCP VM 먼저 삭제 시도 (best-effort) — 실패해도 user 삭제는 진행
			if s.workstations != nil {
				current, _ := s.users.Workstation(body.Email)
				if err := s.workstations.Delete(r.Context(), body.Email, defaultOrgID, current); err != nil {
					log.Printf("workstation delete failed for %s (proceeding with user delete): %v", body.Email, err)
				} else {
					log.Printf("workstation deleted for %s", body.Email)
				}
			}
			// 2) local user store 에서 제거
			if err := s.users.Delete(body.Email); err != nil {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			// 3) org server 에서 제거
			if err := s.orgServer.DeleteUser(defaultOrgID, body.Email); err != nil {
				w.WriteHeader(http.StatusBadGateway)
				json.NewEncoder(w).Encode(map[string]string{"error": "조직 서버 삭제 실패: " + err.Error()})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
			return
		}

		http.NotFound(w, r)
	})

	// POST /api/admin/propose-amendment — wiki가 헌법 개정안 생성 → approval 큐에 등록
	mux.HandleFunc("/api/admin/propose-amendment", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) { return }
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		proposal, err := s.orgServer.ProposeAmendment(defaultOrgID)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		diff, _ := proposal["diff"].(string)
		reasoning, _ := proposal["reasoning"].(string)
		if diff == "" {
			json.NewEncoder(w).Encode(map[string]string{"status": "no_amendment", "reasoning": reasoning})
			return
		}
		// approval 큐에 등록
		id := fmt.Sprintf("apr-%s", randomMachineID()[:12])
		approvalsMu.Lock()
		approvalsStore = append(approvalsStore, map[string]any{
			"id":          id,
			"sessionId":   "constitution",
			"command":     "constitution-amendment:review",
			"args":        []string{"diff=" + diff, "reasoning=" + reasoning},
			"requester":   "wiki-guardrail",
			"org_id":      defaultOrgID,
			"requestedAt": time.Now().UTC().Format(time.RFC3339),
			"status":      "pending",
		})
		approvalsMu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"status": "proposed", "approval_id": id})
	})

	// POST /api/admin/propose-g1-amendment — wiki가 G1 패턴 개정안 생성 → approval 큐에 등록
	mux.HandleFunc("/api/admin/propose-g1-amendment", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) { return }
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		proposal, err := s.orgServer.ProposeG1Amendment(defaultOrgID)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		diff, _ := proposal["diff"].(string)
		reasoning, _ := proposal["reasoning"].(string)
		if diff == "" {
			json.NewEncoder(w).Encode(map[string]string{"status": "no_amendment", "reasoning": reasoning})
			return
		}
		id := fmt.Sprintf("apr-%s", randomMachineID()[:12])
		approvalsMu.Lock()
		approvalsStore = append(approvalsStore, map[string]any{
			"id":          id,
			"sessionId":   "g1-patterns",
			"command":     "g1-amendment:review",
			"args":        []string{"diff=" + diff, "reasoning=" + reasoning},
			"requester":   "wiki-guardrail",
			"org_id":      defaultOrgID,
			"requestedAt": time.Now().UTC().Format(time.RFC3339),
			"status":      "pending",
		})
		approvalsMu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"status": "proposed", "approval_id": id})
	})

	mux.HandleFunc("/api/admin/org-settings", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Allow-Methods", "GET, PATCH, PUT, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Cookie")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if requireEdit(w, r) {
			return
		}
		orgID := resolveOrg(r)
		if s.orgSettings == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "org_settings_unavailable"})
			return
		}
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(s.orgSettings.GetOrCreate(orgID))
			return
		}
		if r.Method == http.MethodPut || r.Method == http.MethodPatch {
			var body struct {
				DisplayName *string                `json:"display_name"`
				Settings    map[string]interface{} `json:"settings"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			rec, err := s.orgSettings.Patch(orgID, body.DisplayName, body.Settings)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(rec)
			return
		}
		http.NotFound(w, r)
	})

	mux.HandleFunc("/api/guardrail/g1-defaults", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"patterns": DefaultG1Patterns,
		})
	})

	mux.HandleFunc("/api/mount/config", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		orgID := resolveOrg(r)
		sandboxRoot := mountRootForOrg(orgID)
		// 경로는 심볼릭 형태로 표시. 사용자마다 다른 환경.
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"org_id":      orgID,
			"mount_root":  sandboxRoot, // 하위 호환
			"allowedDirs": []string{sandboxRoot},
			// 새 구조: S3/S2/S1 경로 각각 + 어떤 env var 에서 왔는지
			"paths": map[string]any{
				"host_s3": map[string]string{
					"env_var": "BOAN_HOST_MOUNT_ROOT",
					"value":   "$HOME/Desktop/boanclaw",
				},
				"sandbox_s2": map[string]string{
					"env_var": "BOAN_MOUNT_ROOT",
					"value":   sandboxRoot,
				},
				"s1_stage": map[string]string{
					"env_var": "GCP Windows VM",
					// SCP 로 직접 GCP Windows VM 의 사용자 Desktop\boanclaw 에 전송.
					"value": `C:\Users\<user>\Desktop\boanclaw`,
				},
			},
		})
	})

	mux.HandleFunc("/api/mount", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Path      string `json:"path"`
			SessionID string `json:"sessionId"`
			ReadOnly  bool   `json:"readOnly"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(body.Path) == "" {
			http.Error(w, "path required", http.StatusBadRequest)
			return
		}
		orgID := resolveOrg(r)
		root := mountRootForOrg(orgID)
		target := filepath.Clean(body.Path)
		if !isWithinMountRoot(root, target) {
			http.Error(w, "mount path must stay under policy mount_root", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"success":    true,
			"mountPoint": target,
			"sessionId":  body.SessionID,
		})
	})

	// ── 파일 매니저 API: S2(sandbox) ↔ S1(RDP staging) 파일 전송 ────────────────────
	// S1 = boan-rdp-transfer 볼륨의 사용자별 staging 디렉토리.
	// boan-sandbox 와 boan-guacd 가 동일 볼륨을 공유하므로, 여기 둔 파일은
	// 사용자의 활성 Guacamole RDP 세션 안에서 BoanClaw 드라이브로 보인다 (RDP virtual channel).
	// SCP/SSH 경유 없음 — 같은 RDP 포트(3389) 내 채널로만 흐름.

	// GET /api/files/list?path=&side=s2|s1 — 디렉토리 내용 조회
	// S2: 로컬 sandbox mount (/home/boan/Desktop/boanclaw)
	// S1: RDP staging dir (/data/rdp-transfer/<email>)
	mux.HandleFunc("/api/files/list", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) { return }
		w.Header().Set("Content-Type", "application/json")
		side := r.URL.Query().Get("side")
		reqPath := r.URL.Query().Get("path")
		orgID := resolveOrg(r)
		root := mountRootForOrg(orgID)

		type fileEntry struct {
			Name     string `json:"name"`
			IsDir    bool   `json:"is_dir"`
			Size     int64  `json:"size"`
			Modified int64  `json:"modified"` // unix seconds, 0 if stat 실패
		}

		switch side {
		case "s2":
			baseDir := root
			target := filepath.Clean(filepath.Join(baseDir, reqPath))
			if !strings.HasPrefix(target, baseDir) {
				http.Error(w, `{"error":"path escapes base directory"}`, http.StatusForbidden)
				return
			}
			if target == baseDir {
				if _, err := os.Stat(baseDir); os.IsNotExist(err) {
					_ = os.MkdirAll(baseDir, 0755)
				}
			}
			entries, err := os.ReadDir(target)
			if err != nil {
				if os.IsNotExist(err) {
					http.Error(w, `{"error":"path not found"}`, http.StatusNotFound)
					return
				}
				http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
				return
			}
			files := make([]fileEntry, 0, len(entries))
			for _, e := range entries {
				info, _ := e.Info()
				size := int64(0)
				modified := int64(0)
				if info != nil {
					size = info.Size()
					modified = info.ModTime().Unix()
				}
				files = append(files, fileEntry{Name: e.Name(), IsDir: e.IsDir(), Size: size, Modified: modified})
			}
			json.NewEncoder(w).Encode(map[string]any{"path": reqPath, "side": side, "files": files})

		case "s1":
			// S1 = RDP staging dir. 인증만 필요 (workstation provision 여부는 무관 — staging 은 항상 존재).
			sess, err := auth.SessionFromRequest(r, s.authProv)
			if err != nil || sess.Email == "" {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]any{"error": "authenticated session required"})
				return
			}
			baseDir := userRDPTransferDir(s.cfg.RDPTransferRoot, sess.Email)
			if _, statErr := os.Stat(baseDir); os.IsNotExist(statErr) {
				_ = ensureRDPTransferDir(baseDir)
			}
			target := filepath.Clean(filepath.Join(baseDir, reqPath))
			if !strings.HasPrefix(target, baseDir) {
				http.Error(w, `{"error":"path escapes base directory"}`, http.StatusForbidden)
				return
			}
			entries, err := os.ReadDir(target)
			if err != nil {
				if os.IsNotExist(err) {
					http.Error(w, `{"error":"path not found"}`, http.StatusNotFound)
					return
				}
				log.Printf("[files/list s1] readdir failed user=%s path=%s err=%v", sess.Email, target, err)
				http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusBadRequest)
				return
			}
			files := make([]fileEntry, 0, len(entries))
			for _, e := range entries {
				info, _ := e.Info()
				size := int64(0)
				modified := int64(0)
				if info != nil {
					size = info.Size()
					modified = info.ModTime().Unix()
				}
				files = append(files, fileEntry{Name: e.Name(), IsDir: e.IsDir(), Size: size, Modified: modified})
			}
			json.NewEncoder(w).Encode(map[string]any{"path": reqPath, "side": side, "files": files})

		default:
			http.Error(w, `{"error":"side must be s2 or s1"}`, http.StatusBadRequest)
			return
		}
	})

	// POST /api/files/transfer — 파일 전송 (S2 ↔ S1 RDP staging)
	// S2→S1: G1 가드레일 검사 후 sandbox 파일을 RDP staging dir 으로 복사. 사용자의 Guacamole 세션에서 BoanClaw 드라이브로 보임.
	// S1→S2: 사용자가 BoanClaw 드라이브에 둔 파일을 sandbox 로 복사. SSH/SCP 사용 안 함.
	mux.HandleFunc("/api/files/transfer", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) { return }
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body struct {
			FileName string `json:"file_name"`
			SrcSide  string `json:"src_side"`  // s2 or s1
			SrcPath  string `json:"src_path"`  // relative path within side
			DstPath  string `json:"dst_path"`  // relative path within other side
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		sess, sessErr := auth.SessionFromRequest(r, s.authProv)
		if sessErr != nil || sess.Email == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"error": "authenticated session required"})
			return
		}

		orgID := resolveOrg(r)
		s2Base := mountRootForOrg(orgID)
		s1Base := userRDPTransferDir(s.cfg.RDPTransferRoot, sess.Email)
		_ = ensureRDPTransferDir(s1Base)

		copyFile := func(src, dst string) (int64, error) {
			in, err := os.Open(src)
			if err != nil {
				return 0, err
			}
			defer in.Close()
			// dst 가 RDP staging dir 안의 중첩 경로일 수 있어서, 새로 만드는
			// 중간 디렉토리도 guacd 가 쓸 수 있게 ensureRDPTransferDir 사용.
			if err := ensureRDPTransferDir(filepath.Dir(dst)); err != nil {
				return 0, err
			}
			out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				return 0, err
			}
			defer out.Close()
			return io.Copy(out, in)
		}

		switch body.SrcSide {
		case "s2":
			// sandbox → RDP staging
			srcFull := filepath.Clean(filepath.Join(s2Base, body.SrcPath, body.FileName))
			if !strings.HasPrefix(srcFull, s2Base) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]any{"error": "source path escapes S2 base"})
				return
			}
			info, err := os.Stat(srcFull)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]any{"error": "source file not found"})
				return
			}
			if info.IsDir() {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{"error": "directory transfer not allowed, files only"})
				return
			}

			// 가드레일 — 텍스트 파일 G1 검사
			content, readErr := os.ReadFile(srcFull)
			if readErr != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]any{"error": "cannot read source file"})
				return
			}
			textContent := string(content)
			if len(textContent) > 0 {
				gateResp := evaluateInputGateWithLocal(r.Context(), s.dlpEng, s.guardrail, s.evaluateGuardrailLocal, orgID, InputGateRequest{
					Mode: "text", Text: textContent, SrcLevel: 2, DestLevel: 1,
					Flow: "file-transfer-s2-to-s1", AccessLevel: "allow",
				}, nil)
				if !gateResp.Allowed {
					json.NewEncoder(w).Encode(map[string]any{
						"ok": false, "error": "guardrail blocked file transfer",
						"action": gateResp.Action, "reason": gateResp.Reason,
					})
					return
				}
			}

			dstFull := filepath.Clean(filepath.Join(s1Base, body.DstPath, body.FileName))
			if !strings.HasPrefix(dstFull, s1Base) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]any{"error": "dest path escapes S1 staging"})
				return
			}
			n, err := copyFile(srcFull, dstFull)
			if err != nil {
				log.Printf("[files/transfer s2→s1] copy failed user=%s err=%v", sess.Email, err)
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "copy failed: " + err.Error()})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"ok": true, "src": srcFull, "dst": dstFull,
				"size": n, "guardrail": true,
			})

		case "s1":
			// RDP staging → sandbox
			srcFull := filepath.Clean(filepath.Join(s1Base, body.SrcPath, body.FileName))
			if !strings.HasPrefix(srcFull, s1Base) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]any{"error": "source path escapes S1 staging"})
				return
			}
			info, err := os.Stat(srcFull)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]any{"error": "source file not found in S1 staging"})
				return
			}
			if info.IsDir() {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]any{"error": "directory transfer not allowed, files only"})
				return
			}
			dstFull := filepath.Clean(filepath.Join(s2Base, body.DstPath, body.FileName))
			if !strings.HasPrefix(dstFull, s2Base) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]any{"error": "dest path escapes S2 base"})
				return
			}
			n, err := copyFile(srcFull, dstFull)
			if err != nil {
				log.Printf("[files/transfer s1→s2] copy failed user=%s err=%v", sess.Email, err)
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "copy failed: " + err.Error()})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"ok": true, "src": srcFull, "dst": dstFull,
				"size": n, "guardrail": false,
			})

		default:
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]any{"error": "src_side must be s2 or s1"})
		}
	})

	// ── Observability API ────────────────────────────────────────────────────
	// GET: 검색+페이지네이션 ?limit=50&offset=0&type=chat&q=검색어
	// DELETE: 로그 비우기
	mux.HandleFunc("/api/observability/traces", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) { return }
		w.Header().Set("Content-Type", "application/json")

		// DELETE: 로그 비우기
		if r.Method == http.MethodDelete {
			traceMu.Lock()
			traceStore = nil
			traceMu.Unlock()
			json.NewEncoder(w).Encode(map[string]string{"status": "cleared"})
			return
		}

		limit := 50
		if v := r.URL.Query().Get("limit"); v != "" { fmt.Sscanf(v, "%d", &limit) }
		if limit <= 0 { limit = 50 }
		if limit > 500 { limit = 500 }
		offset := 0
		if v := r.URL.Query().Get("offset"); v != "" { fmt.Sscanf(v, "%d", &offset) }

		typeFilter := r.URL.Query().Get("type")
		query := strings.ToLower(r.URL.Query().Get("q"))

		// 1년 이상 된 항목 자동 삭제
		cutoff := time.Now().UTC().AddDate(-1, 0, 0).Format(time.RFC3339)
		traceMu.Lock()
		cleaned := traceStore[:0]
		for _, t := range traceStore {
			if t.Timestamp >= cutoff { cleaned = append(cleaned, t) }
		}
		traceStore = cleaned

		// 필터링
		var filtered []traceEntry
		for i := len(traceStore) - 1; i >= 0; i-- {
			t := traceStore[i]
			if typeFilter != "" && t.Type != typeFilter { continue }
			if query != "" && !strings.Contains(strings.ToLower(t.Summary), query) &&
				!strings.Contains(strings.ToLower(t.Source), query) &&
				!strings.Contains(strings.ToLower(t.Decision), query) { continue }
			filtered = append(filtered, t)
		}
		total := len(filtered)
		traceMu.Unlock()

		// 페이지네이션
		if offset >= len(filtered) { filtered = nil }
		if offset < len(filtered) {
			end := offset + limit
			if end > len(filtered) { end = len(filtered) }
			filtered = filtered[offset:end]
		}
		if filtered == nil { filtered = []traceEntry{} }

		json.NewEncoder(w).Encode(map[string]any{
			"total":  total,
			"offset": offset,
			"limit":  limit,
			"traces": filtered,
		})
	})

	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/status/dlp", s.handleDLPStatus)
	mux.HandleFunc("/status/network-gate", s.handleGateStatus)
	mux.HandleFunc("/status/credentials", s.handleCredentialStatus)
	mux.HandleFunc("/status/routing", s.handleRoutingStatus)

	policyBase := s.cfg.PolicyURL
	registryBase := s.cfg.LLMRegistryURL
	credBase := s.cfg.CredentialFilterURL

	proxy := func(w http.ResponseWriter, r *http.Request, target string) {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}

	mux.HandleFunc("/api/policy/", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		orgID := resolveOrg(r)
		rest := strings.TrimPrefix(r.URL.Path, "/api/policy")
		switch {
		case rest == "/v1/policy" && r.Method == http.MethodGet:
			req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet,
				policyBase+"/org/"+orgID+"/policy.json", nil)
			resp, err := client.Do(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Access-Control-Allow-Origin", "*")
				json.NewEncoder(w).Encode(map[string]any{
					"version":           0,
					"org_id":            orgID,
					"network_whitelist": []any{},
					"dlp_rules":         []any{},
					"rbac":              map[string]any{},
				})
				return
			}
			raw, _ := io.ReadAll(resp.Body)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(resp.StatusCode)
			w.Write(raw)

		case rest == "/v1/policy" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
			if requireEdit(w, r) {
				return
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			raw, _ := json.Marshal(body)
			req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost,
				policyBase+"/org/"+orgID+"/policy", bytes.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			respRaw, _ := io.ReadAll(resp.Body)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(resp.StatusCode)
			w.Write(respRaw)
		case rest == "/v1/policy/rollback" && r.Method == http.MethodPost:
			if requireEdit(w, r) {
				return
			}
			proxy(w, r, policyBase+"/org/"+orgID+"/policy/rollback/1")
		default:
			http.NotFound(w, r)
		}
	})

	mux.HandleFunc("/api/registry/", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		rest := strings.TrimPrefix(r.URL.Path, "/api/registry")
		switch {
		case rest == "/v1/llms" && r.Method == http.MethodGet:
			proxy(w, r, registryBase+"/llm/list")
		case rest == "/v1/llms/history" && r.Method == http.MethodGet:
			proxy(w, r, registryBase+"/llm/history")
		case rest == "/v1/llms" && r.Method == http.MethodPost:
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			orgID := resolveOrg(r)
			name, _ := body["name"].(string)
			storeDetected, _ := body["store_detected_credentials"].(bool)
			if curlTemplate, _ := body["curl_template"].(string); strings.TrimSpace(curlTemplate) != "" && strings.TrimSpace(name) != "" {
				keys := detectRegistryCredentialKeys(curlTemplate)
				if len(keys) > 0 {
					if storeDetected {
						role := strings.TrimSpace(name) + "-apikey"
						for _, key := range keys {
							credRaw, _ := json.Marshal(map[string]any{
								"role":      role,
								"key":       key,
								"ttl_hours": 8760,
							})
							req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, credBase+"/credential/"+orgID, bytes.NewReader(credRaw))
							req.Header.Set("Content-Type", "application/json")
							resp, err := client.Do(req)
							if err != nil {
								http.Error(w, err.Error(), http.StatusBadGateway)
								return
							}
							resp.Body.Close()
							if resp.StatusCode >= 300 {
								http.Error(w, "failed to store detected credential", http.StatusBadGateway)
								return
							}
						}
					}
					body["curl_template"] = sanitizeRegistryCurl(curlTemplate, strings.TrimSpace(name))
				}
			}
			if imageCurlTemplate, _ := body["image_curl_template"].(string); strings.TrimSpace(imageCurlTemplate) != "" && strings.TrimSpace(name) != "" {
				keys := detectRegistryCredentialKeys(imageCurlTemplate)
				if len(keys) > 0 {
					if storeDetected {
						role := strings.TrimSpace(name) + "-apikey"
						for _, key := range keys {
							credRaw, _ := json.Marshal(map[string]any{
								"role":      role,
								"key":       key,
								"ttl_hours": 8760,
							})
							req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, credBase+"/credential/"+orgID, bytes.NewReader(credRaw))
							req.Header.Set("Content-Type", "application/json")
							resp, err := client.Do(req)
							if err != nil {
								http.Error(w, err.Error(), http.StatusBadGateway)
								return
							}
							resp.Body.Close()
							if resp.StatusCode >= 300 {
								http.Error(w, "failed to store detected credential", http.StatusBadGateway)
								return
							}
						}
					}
					body["image_curl_template"] = sanitizeRegistryCurl(imageCurlTemplate, strings.TrimSpace(name))
				}
			}
			delete(body, "store_detected_credentials")

			// 등록 전에 실제 호출 테스트 (credential 치환 후 ping)
			testCurl, _ := body["curl_template"].(string)
			if testCurl == "" {
				testCurl, _ = body["image_curl_template"].(string)
			}
			if testCurl != "" {
				if err := s.testRegistryLLMCurl(r.Context(), orgID, testCurl); err != nil {
					log.Printf("[register-test] FAILED: %v", err)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{
						"error":  "LLM 등록 테스트 실패",
						"detail": err.Error(),
					})
					return
				}
				log.Printf("[register-test] OK: name=%s", strings.TrimSpace(name))
			}

			raw, _ := json.Marshal(body)
			r.Body = io.NopCloser(bytes.NewReader(raw))
			proxy(w, r, registryBase+"/llm/register")
		default:
			if strings.HasSuffix(rest, "/bind-security-lmm") {
				name := strings.TrimSuffix(strings.TrimPrefix(rest, "/v1/llms/"), "/bind-security-lmm")
				proxy(w, r, registryBase+"/llm/"+name+"/bind-security-lmm")
				return
			}
			if strings.HasSuffix(rest, "/bind-security") {
				name := strings.TrimSuffix(strings.TrimPrefix(rest, "/v1/llms/"), "/bind-security")
				proxy(w, r, registryBase+"/llm/"+name+"/bind-security")
				return
			}
			// /v1/llms/{name}/bind-role/{role} 또는 /v1/llms/{name}/unbind-role/{role}
			pathOnly := strings.TrimPrefix(rest, "/v1/llms/")
			if strings.Contains(pathOnly, "/bind-role/") || strings.Contains(pathOnly, "/unbind-role/") {
				proxy(w, r, registryBase+"/llm/"+pathOnly)
				return
			}
			name := strings.TrimPrefix(rest, "/v1/llms/")
			if name != "" && r.Method == http.MethodDelete {
				proxy(w, r, registryBase+"/llm/"+name)
				return
			}
			http.NotFound(w, r)
		}
	})

	mux.HandleFunc("/api/audit/", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		auditTotal := uint64(0)
		auditBlocked := uint64(0)
		if s.audit != nil {
			auditTotal = s.audit.TotalEvents()
			auditBlocked = s.audit.BlockedEvents()
		}
		json.NewEncoder(w).Encode([]map[string]any{
			{
				"id":        "sys-1",
				"action":    "summary",
				"s_level":   "S2",
				"host":      "boan-proxy",
				"user":      "system",
				"timestamp": time.Now().UTC().Format(time.RFC3339),
				"details":   map[string]any{"total": auditTotal, "blocked": auditBlocked},
			},
		})
	})

	mux.HandleFunc("/api/credential/v1/store", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		orgID := resolveOrg(r)
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Role     string `json:"role"`
			Key      string `json:"key"`
			TTLHours int    `json:"ttl_hours"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if body.TTLHours == 0 {
			body.TTLHours = 8760
		}
		raw, _ := json.Marshal(map[string]any{
			"role":      body.Role,
			"key":       body.Key,
			"ttl_hours": body.TTLHours,
		})
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost,
			credBase+"/credential/"+orgID, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(resp.StatusCode)
		json.NewEncoder(w).Encode(map[string]any{"status": "stored", "role": body.Role})
	})

	// ── Credential 등록 추천 (org-wide) ─────────────────────────────────
	// 소유자가 role_name + description 으로 추천 등록 → 전체 사용자 개인 탭에 표시
	// 각 사용자가 fulfill 하면 자기 이메일 기준 personal-{emailPrefix}-{role} 키 생성
	// 추천 자체는 사라지지 않음 (다른 사용자도 계속 보임)
	mux.HandleFunc("/api/credential-requests", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) { return }
		w.Header().Set("Content-Type", "application/json")

		if r.Method == http.MethodGet {
			credReqMu.Lock()
			out := make([]credentialRequest, 0, len(credReqStore))
			out = append(out, credReqStore...)
			credReqMu.Unlock()
			json.NewEncoder(w).Encode(out)
			return
		}

		if r.Method == http.MethodPost {
			var body struct {
				RoleName    string `json:"role_name"`
				Description string `json:"description"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			body.RoleName = strings.TrimSpace(body.RoleName)
			if body.RoleName == "" {
				http.Error(w, `{"error":"role_name required"}`, http.StatusBadRequest)
				return
			}
			// 중복 role_name 방지
			credReqMu.Lock()
			for _, existing := range credReqStore {
				if existing.RoleName == body.RoleName {
					credReqMu.Unlock()
					http.Error(w, `{"error":"role_name already recommended"}`, http.StatusConflict)
					return
				}
			}
			id := fmt.Sprintf("creq-%s", randomMachineID()[:12])
			cr := credentialRequest{
				ID: id, RoleName: body.RoleName,
				Description: strings.TrimSpace(body.Description),
				CreatedAt:   time.Now().UTC().Format(time.RFC3339),
			}
			credReqStore = append(credReqStore, cr)
			credReqMu.Unlock()
			json.NewEncoder(w).Encode(cr)
			return
		}
		http.NotFound(w, r)
	})

	// POST /api/credential-requests/{id}/fulfill — 사용자가 본인 personal 키 등록
	// DELETE /api/credential-requests/{id} — 소유자가 추천 삭제
	mux.HandleFunc("/api/credential-requests/", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) { return }
		w.Header().Set("Content-Type", "application/json")
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/credential-requests/"), "/")
		reqID := parts[0]

		// DELETE: 소유자가 추천 삭제
		if r.Method == http.MethodDelete && len(parts) == 1 {
			credReqMu.Lock()
			for i, cr := range credReqStore {
				if cr.ID == reqID {
					credReqStore = append(credReqStore[:i], credReqStore[i+1:]...)
					break
				}
			}
			credReqMu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if len(parts) < 2 || parts[1] != "fulfill" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}

		// 세션에서 사용자 이메일 추출
		sess, err := auth.SessionFromRequest(r, s.authProv)
		if err != nil || sess.Email == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]any{"error": "authenticated session required"})
			return
		}

		var body struct {
			Key      string `json:"key"`
			TTLHours int    `json:"ttl_hours"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Key == "" {
			http.Error(w, `{"error":"key required"}`, http.StatusBadRequest)
			return
		}
		if body.TTLHours <= 0 { body.TTLHours = 8760 }

		// 추천 찾기 (status 로 필터링 X — 계속 유지)
		credReqMu.Lock()
		var roleName string
		for i := range credReqStore {
			if credReqStore[i].ID == reqID {
				roleName = credReqStore[i].RoleName
				break
			}
		}
		credReqMu.Unlock()
		if roleName == "" {
			http.Error(w, `{"error":"recommendation not found"}`, http.StatusNotFound)
			return
		}

		// credential-filter에 등록: personal-{emailPrefix}-{role}
		orgID := sess.OrgID
		if orgID == "" {
			orgID = resolveOrg(r)
		}
		personalRole := fmt.Sprintf("personal-%s-%s", strings.Split(sess.Email, "@")[0], roleName)
		raw, _ := json.Marshal(map[string]any{"role": personalRole, "key": body.Key, "ttl_hours": body.TTLHours})
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost, credBase+"/credential/"+orgID, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		resp.Body.Close()
		json.NewEncoder(w).Encode(map[string]string{"status": "fulfilled", "role": personalRole})
	})

	mux.HandleFunc("/api/credential/", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		orgID := resolveOrg(r)
		rest := strings.TrimPrefix(r.URL.Path, "/api/credential")
		switch {
		case rest == "/v1/credentials" && r.Method == http.MethodGet:
			req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, credBase+"/credential/"+orgID, nil)
			resp, err := client.Do(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(resp.StatusCode)
			w.Write(raw)

		case rest == "/v1/credentials" && r.Method == http.MethodPost:
			var body struct {
				Name     string `json:"name"`
				Provider string `json:"provider"`
				Key      string `json:"key"`
				TTLHours int    `json:"ttl_hours"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.TTLHours == 0 {
				body.TTLHours = 8760
			}
			raw, _ := json.Marshal(map[string]any{
				"role":      body.Name,
				"key":       body.Key,
				"ttl_hours": body.TTLHours,
			})
			req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost,
				credBase+"/credential/"+orgID, bytes.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(resp.StatusCode)
			json.NewEncoder(w).Encode(map[string]any{"status": "stored", "role": body.Name})

		case rest == "/v1/passthrough" && r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			json.NewEncoder(w).Encode(s.listCredentialPassthrough(orgID))

		case rest == "/v1/passthrough" && r.Method == http.MethodPost:
			var body struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if err := s.upsertCredentialPassthrough(orgID, body.Name, body.Value); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			json.NewEncoder(w).Encode(map[string]any{"status": "stored", "name": strings.TrimSpace(body.Name)})

		default:
			// passthrough DELETE: /v1/passthrough/{name}
			if strings.HasPrefix(rest, "/v1/passthrough/") && r.Method == http.MethodDelete {
				name := strings.TrimPrefix(rest, "/v1/passthrough/")
				if name == "" {
					http.NotFound(w, r)
					return
				}
				if err := s.deleteCredentialPassthrough(orgID, name); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			// credentials DELETE: /v1/credentials/{role}
			if strings.HasPrefix(rest, "/v1/credentials/") && r.Method == http.MethodDelete {
				id := strings.TrimPrefix(rest, "/v1/credentials/")
				if id == "" {
					http.NotFound(w, r)
					return
				}
				req, _ := http.NewRequestWithContext(r.Context(), http.MethodDelete,
					credBase+"/credential/"+orgID+"/"+id, nil)
				resp, err := client.Do(req)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadGateway)
					return
				}
				defer resp.Body.Close()
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.WriteHeader(resp.StatusCode)
				return
			}
			http.NotFound(w, r)
		}
	})

	mux.HandleFunc("/api/gcp/org", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body struct {
			AccessToken string `json:"access_token"`
			OrgID       string `json:"org_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if body.AccessToken == "" {
			http.Error(w, "access_token required", http.StatusBadRequest)
			return
		}
		gcpClient := &http.Client{Timeout: 10 * time.Second}
		var gcpURL string
		if body.OrgID != "" {
			gcpURL = "https://cloudresourcemanager.googleapis.com/v3/organizations/" + body.OrgID
		} else {
			gcpURL = "https://cloudresourcemanager.googleapis.com/v3/organizations:search"
		}
		gcpReq, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, gcpURL, nil)
		gcpReq.Header.Set("Authorization", "Bearer "+body.AccessToken)
		gcpResp, err := gcpClient.Do(gcpReq)
		if err != nil {
			http.Error(w, "GCP API error: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer gcpResp.Body.Close()
		raw, _ := io.ReadAll(gcpResp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(gcpResp.StatusCode)
		w.Write(raw)
	})

	mux.HandleFunc("/api/gcp/sync", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body struct {
			AccessToken  string   `json:"access_token"`
			OrgID        string   `json:"org_id"`
			OrgName      string   `json:"org_name"`
			AllowDomains []string `json:"allow_domains"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		orgID := resolveOrg(r)
		network := []map[string]any{}
		for _, d := range body.AllowDomains {
			network = append(network, map[string]any{"host": d, "ports": []int{443}})
		}
		newPolicy := map[string]any{
			"org_id":            orgID,
			"network_whitelist": network,
			"features": map[string]bool{
				"gcp_sync": true,
			},
			"gcp_org_id":   body.OrgID,
			"gcp_org_name": body.OrgName,
		}
		raw, _ := json.Marshal(newPolicy)
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodPut,
			policyBase+"/org/"+orgID+"/policy.json", bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(resp.StatusCode)
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "synced",
			"org_id":  body.OrgID,
			"domains": len(body.AllowDomains),
		})
	})

	mux.HandleFunc("/api/approvals", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		approvalsMu.Lock()
		list := make([]map[string]any, len(approvalsStore))
		copy(list, approvalsStore)
		approvalsMu.Unlock()
		if list == nil {
			list = []map[string]any{}
		}
		json.NewEncoder(w).Encode(list)
	})

	mux.HandleFunc("/api/approvals/", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/approvals/"), "/")
		id := parts[0]

		// GET /api/approvals/{id} — single record lookup for HITL polling
		if r.Method == http.MethodGet && len(parts) == 1 && id != "" {
			w.Header().Set("Content-Type", "application/json")
			approvalsMu.Lock()
			var found map[string]any
			for _, a := range approvalsStore {
				if a["id"] == id {
					found = a
					break
				}
			}
			approvalsMu.Unlock()
			if found == nil {
				http.NotFound(w, r)
				return
			}
			json.NewEncoder(w).Encode(found)
			return
		}

		if len(parts) < 2 || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		action := parts[1]
		status := action
		switch action {
		case "approve":
			status = "approved"
		case "reject":
			status = "rejected"
		}
		var (
			declinedFPs []string
			orgID       string
			candidates  []credentialApprovalCandidate
		)
		approvalsMu.Lock()
		for _, a := range approvalsStore {
			if a["id"] == id {
				if v, ok := a["org_id"].(string); ok {
					orgID = v
				}
				if stored, ok := pendingCredentialApprovals[id]; ok {
					candidates = append(candidates, stored...)
				}
				if status == "rejected" {
					if fps, ok := a["credential_fingerprints"].([]string); ok {
						declinedFPs = fps
					} else if fpsAny, ok := a["credential_fingerprints"].([]any); ok {
						for _, fp := range fpsAny {
							if str, ok := fp.(string); ok {
								declinedFPs = append(declinedFPs, str)
							}
						}
					}
				}
				break
			}
		}
		approvalsMu.Unlock()
		if status == "approved" && len(candidates) > 0 {
			for _, candidate := range candidates {
				raw, _ := json.Marshal(map[string]any{
					"role":      candidate.Role,
					"key":       candidate.Key,
					"ttl_hours": 8760,
				})
				req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost,
					credBase+"/credential/"+orgID, bytes.NewReader(raw))
				req.Header.Set("Content-Type", "application/json")
				resp, err := client.Do(req)
				if err != nil {
					http.Error(w, "failed to persist approved credential: "+err.Error(), http.StatusBadGateway)
					return
				}
				resp.Body.Close()
				if resp.StatusCode >= 300 {
					http.Error(w, "failed to persist approved credential", http.StatusBadGateway)
					return
				}
			}
		}
		// approval 레코드에서 메타데이터 추출 (training log 피드백용)
		var approvalText, approvalMode, approvalReason, approvalRequester string
		approvalsMu.Lock()
		for i, a := range approvalsStore {
			if a["id"] == id {
				approvalsStore[i]["status"] = status
				approvalsStore[i]["decided_at"] = time.Now().UTC().Format(time.RFC3339)
				// guardrail 관련 approval이면 training log에 피드백
				if cmd, _ := a["command"].(string); strings.Contains(cmd, "guardrail") {
					if args, ok := a["args"].([]any); ok {
						for _, arg := range args {
							s := fmt.Sprint(arg)
							if strings.HasPrefix(s, "text=") {
								approvalText = strings.TrimPrefix(s, "text=")
							} else if strings.HasPrefix(s, "mode=") {
								approvalMode = strings.TrimPrefix(s, "mode=")
							} else if strings.HasPrefix(s, "reason=") {
								approvalReason = strings.TrimPrefix(s, "reason=")
							}
						}
					}
					approvalRequester, _ = a["requester"].(string)
				}
				break
			}
		}
		delete(pendingCredentialApprovals, id)
		approvalsMu.Unlock()

		// constitution-amendment 승인 시 실제 정책에 반영
		approvalsMu.Lock()
		for _, a := range approvalsStore {
			if a["id"] == id && status == "approved" {
				cmd, _ := a["command"].(string)
				if cmd == "constitution-amendment:review" || cmd == "g1-amendment:review" {
					if args, ok := a["args"].([]any); ok {
						var diffText string
						for _, arg := range args {
							s := fmt.Sprint(arg)
							if strings.HasPrefix(s, "diff=") {
								diffText = strings.TrimPrefix(s, "diff=")
							}
						}
						if diffText != "" && orgID != "" {
							// Apply amendment: send diff to policy server as update
							if cmd == "constitution-amendment:review" {
								// G2 constitution diff — extract new text from diff
								go func() {
									newConstitution := applyConstitutionDiff(diffText)
									if newConstitution != "" {
										s.orgServer.UpdatePolicy(orgID, map[string]any{
											"guardrail": map[string]any{"constitution": newConstitution},
										})
										log.Printf("[amendment] G2 constitution applied from diff")
									}
								}()
							}
							log.Printf("[amendment] %s approved and applied", cmd)
						}
					}
				}
				break
			}
		}
		approvalsMu.Unlock()

		// 인간 결정 → wiki training log에 피드백 (Tier 2 학습)
		if approvalText != "" && orgID != "" {
			decision := "reject"
			if status == "approved" {
				decision = "approve"
			}
			go s.orgServer.AppendTrainingLog(orgID, map[string]any{
				"text":           approvalText,
				"mode":           approvalMode,
				"flagged_reason": approvalReason,
				"decision":       decision,
				"reasoning":      "human decision by owner",
				"confidence":     1.0,
				"source":         "human",
				"decided_by":     approvalRequester,
			})
		}

		// Persist declined fingerprints outside the lock.
		for _, fp := range declinedFPs {
			s.declinedFPs.AddFingerprint(fp)
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusNoContent)
	})

	// ── Computer Use — browser-side command queue ────────────────────────────
	// boan-agent tools call POST /api/computer-use/execute which queues a
	// command and blocks until the admin-console frontend executes it in the
	// already-open Guacamole iframe (no new RDP session, no disconnect).
	// The frontend polls GET /api/computer-use/poll and posts results back via
	// POST /api/computer-use/result/{id}.

	// POST /api/computer-use/execute  — called by boan-agent tools
	mux.HandleFunc("/api/computer-use/execute", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		var params map[string]any
		if err := json.Unmarshal(bodyBytes, &params); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		// computer-use type/key 액션은 S1으로 정보가 흐르므로 input-gate 검사 필수
		action, _ := params["action"].(string)
		if action == "type" {
			text, _ := params["text"].(string)
			if text != "" {
				gateResp := evaluateInputGateWithLocal(r.Context(), s.dlpEng, s.guardrail, s.evaluateGuardrailLocal, defaultOrgID, InputGateRequest{
					Mode: "text", Text: text, SrcLevel: 3, DestLevel: 1,
					Flow: "computer-use-type-to-remote-workstation",
				}, nil)
				if !gateResp.Allowed {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]any{"error": "input-gate blocked", "action": gateResp.Action, "reason": gateResp.Reason})
					return
				}
			}
		}

		idBytes := make([]byte, 8)
		crand.Read(idBytes)
		id := hex.EncodeToString(idBytes)
		done := make(chan []byte, 1)

		cuQueueMu.Lock()
		cuPendingQueue = append(cuPendingQueue, &cuQueuedCmd{id: id, params: params, done: done})
		cuQueueMu.Unlock()

		select {
		case result := <-done:
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Write(result)
		case <-time.After(45 * time.Second):
			cuQueueMu.Lock()
			for i, c := range cuPendingQueue {
				if c.id == id {
					cuPendingQueue = append(cuPendingQueue[:i], cuPendingQueue[i+1:]...)
					break
				}
			}
			for i, c := range cuInFlight {
				if c.id == id {
					cuInFlight = append(cuInFlight[:i], cuInFlight[i+1:]...)
					break
				}
			}
			cuQueueMu.Unlock()
			http.Error(w, `{"error":"timeout waiting for browser to execute command"}`, http.StatusGatewayTimeout)
		case <-r.Context().Done():
		}
	})

	// GET /api/computer-use/poll  — called by the admin-console frontend
	//
	// Stale-client guard:
	//   클라이언트는 ?ready=1 query 를 반드시 붙여야 함. 이게 없는 polling 은 옛 cached
	//   bundle 이거나 iframe ref 가 없는 stale client 로 간주 → 빈 응답으로 무시.
	//   active client 만 액션을 claim 해서 silent fail 방지.
	mux.HandleFunc("/api/computer-use/poll", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		// Stale client 차단 — ready=1 없으면 빈 응답 즉시 (long-poll 도 안 함)
		if r.URL.Query().Get("ready") != "1" {
			json.NewEncoder(w).Encode(map[string]any{"id": nil, "stale": true})
			return
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			cuQueueMu.Lock()
			if len(cuPendingQueue) > 0 {
				cmd := cuPendingQueue[0]
				cuPendingQueue = cuPendingQueue[1:]
				cuInFlight = append(cuInFlight, cmd)
				cuQueueMu.Unlock()
				json.NewEncoder(w).Encode(map[string]any{
					"id":     cmd.id,
					"params": cmd.params,
				})
				return
			}
			cuQueueMu.Unlock()
			select {
			case <-r.Context().Done():
				json.NewEncoder(w).Encode(map[string]any{"id": nil})
				return
			case <-time.After(150 * time.Millisecond):
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"id": nil})
	})

	// POST /api/computer-use/result/{id}  — called by the admin-console frontend
	mux.HandleFunc("/api/computer-use/result/", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/computer-use/result/")
		id = strings.Trim(id, "/")
		result, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// 클릭/액션 결과 디버그 로그 (스크린샷 제외)
		if !strings.Contains(string(result), `"media_type"`) {
			log.Printf("[cu-result] id=%s body=%s", id, string(result))
		}
		cuQueueMu.Lock()
		for i, cmd := range cuInFlight {
			if cmd.id == id {
				cuInFlight = append(cuInFlight[:i], cuInFlight[i+1:]...)
				cuQueueMu.Unlock()
				select {
				case cmd.done <- result:
				default:
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		cuQueueMu.Unlock()
		http.Error(w, "command not found: "+id, http.StatusNotFound)
	})

	// GET /api/computer-use/screenshot/{id}.jpg — chat 인젝트용 screenshot 서빙
	// inline base64 가 OpenClaw markdown 렌더러에서 깨지는 문제 회피용.
	// boan-proxy 메모리에 저장된 JPEG 를 그대로 서빙. CORS 허용.
	mux.HandleFunc("/api/computer-use/screenshot/", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/computer-use/screenshot/")
		id = strings.TrimSuffix(id, ".jpg")
		id = strings.TrimSuffix(id, ".jpeg")
		id = strings.Trim(id, "/")
		if id == "" {
			http.NotFound(w, r)
			return
		}
		jpegBytes, ok := loadChatScreenshot(id)
		if !ok {
			http.Error(w, "screenshot not found or expired", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "image/jpeg")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Write(jpegBytes)
	})

	// POST /api/chat/forward — 메시지를 BoanClaw(OpenClaw) 채팅으로 전달
	mux.HandleFunc("/api/chat/forward", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Message string `json:"message"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Message) == "" {
			http.Error(w, `{"error":"message required"}`, http.StatusBadRequest)
			return
		}
		msg := strings.TrimSpace(req.Message)
		// 채팅 메시지도 S1으로 가므로 input-gate 검사
		gateResp := evaluateInputGateWithLocal(r.Context(), s.dlpEng, s.guardrail, s.evaluateGuardrailLocal, defaultOrgID, InputGateRequest{
			Mode: "text", Text: msg, SrcLevel: 3, DestLevel: 1,
			Flow: "openclaw-chat-to-agent",
		}, nil)
		if !gateResp.Allowed {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "input-gate: " + gateResp.Reason, "action": gateResp.Action})
			return
		}
		idKey := hex.EncodeToString(func() []byte { b := make([]byte, 8); crand.Read(b); return b }())
		runID, sendErr := openClawChatSend(msg, idKey)
		w.Header().Set("Content-Type", "application/json")
		if sendErr != nil {
			log.Printf("[chat/forward] chat.send error: %v", sendErr)
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": sendErr.Error()})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "runId": runID})
	})

	// POST /api/chat/inject — role("user"|"assistant") 말풍선을 OpenClaw에 주입 (AI 트리거 없음)
	mux.HandleFunc("/api/chat/inject", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Content) == "" {
			http.Error(w, `{"error":"content required"}`, http.StatusBadRequest)
			return
		}
		role := req.Role
		if role != "user" && role != "assistant" {
			role = "assistant"
		}
		injectOpenClawMessageWithRole(strings.TrimSpace(req.Content), role)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	// POST /api/operator/action — unified operator path for chat / gcp_send / gcp_exec
	mux.HandleFunc("/api/operator/action", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		sess, err := auth.SessionFromRequest(r, s.authProv)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": false})
			return
		}
		var req struct {
			Mode   string `json:"mode"`
			Prompt string `json:"prompt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid payload"}`, http.StatusBadRequest)
			return
		}
		mode := strings.TrimSpace(req.Mode)
		prompt := strings.TrimSpace(req.Prompt)
		if prompt == "" {
			http.Error(w, `{"error":"prompt required"}`, http.StatusBadRequest)
			return
		}
		if mode == "" {
			mode = "chat"
		}
		w.Header().Set("Content-Type", "application/json")

		// gcp_send / gcp_exec: chat.send로 유저버블 표시 후 실행
		if mode == "gcp_send" || mode == "gcp_exec" {
			prefix := map[string]string{"gcp_send": "[gcp_send]", "gcp_exec": "[gcp_exec]"}[mode]
			taggedMsg := prefix + " " + prompt
			idKey := hex.EncodeToString(func() []byte { b := make([]byte, 8); crand.Read(b); return b }())
			runID, err := openClawChatSend(taggedMsg, idKey)
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "mode": mode, "runId": runID})
			return
		}

		result, err := dispatchOperatorAction(r.Context(), sess.Email, sess.OrgID, mode, prompt, nil)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "mode": mode, "result": result})
	})

	// POST /api/computer-use/agent — 사람처럼 동작하는 computer-use 에이전트 루프.
	// 핵심 원칙 (human-like behavior):
	//   1. 키보드 단축키를 먼저 고려 (ctrl+s, alt+F4, Return, Escape ...)
	//   2. 화면 변화(base64 diff)로 '클릭이 실제로 먹혔는지' 판단
	//   3. 같은 액션을 반복하지 않도록 서명 기반 중복 가드
	//   4. 액션 타입별로 UI 반응 대기시간 차등 (type/dialog 유발 키는 더 길게)
	//   5. Vision LMM 한 번 호출로 OBSERVATION / STATUS / NEXT_ACTION 모두 결정
	// NDJSON 스트리밍으로 각 단계(스크린샷, AI 응답, 액션 실행 결과)를 실시간 전송
	mux.HandleFunc("/api/computer-use/agent", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var agentReq struct {
			Prompt string `json:"prompt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&agentReq); err != nil || strings.TrimSpace(agentReq.Prompt) == "" {
			http.Error(w, `{"error":"prompt required"}`, http.StatusBadRequest)
			return
		}
		_ = resolveOrg(r) // orgID 는 향후 감사/로깅 확장용. 현재 루프는 시스템 LMM 하나만 사용.
		log.Printf("[computer-use/agent] received prompt=%q", agentReq.Prompt)

		// 스트리밍 NDJSON — nginx buffering 비활성화
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, canFlush := w.(http.Flusher)

		sendEvent := func(evt map[string]any) {
			json.NewEncoder(w).Encode(evt)
			if canFlush {
				flusher.Flush()
			}
		}

		// computer-use 큐에 액션을 넣고 프론트엔드 실행 결과를 대기.
		// r.Context() 가 취소돼도 (프론트 연결 종료) 에이전트 루프는 계속 실행.
		queueAndWait := func(action map[string]any) (map[string]any, error) {
			resultCh := make(chan []byte, 1)
			idBytes := make([]byte, 8)
			crand.Read(idBytes)
			cmdID := hex.EncodeToString(idBytes)
			cuQueueMu.Lock()
			cuPendingQueue = append(cuPendingQueue, &cuQueuedCmd{id: cmdID, params: action, done: resultCh})
			cuQueueMu.Unlock()
			select {
			case data := <-resultCh:
				var result map[string]any
				json.Unmarshal(data, &result)
				return result, nil
			case <-time.After(45 * time.Second):
				return nil, fmt.Errorf("timeout")
			}
		}

		visionEntry, visionErr := s.loadSecurityLMM(r.Context())
		if visionErr != nil {
			log.Printf("[computer-use/agent] no security LMM: %v", visionErr)
			sendEvent(map[string]any{"type": "error", "text": "보안 LMM이 등록되지 않았습니다: " + visionErr.Error()})
			return
		}
		log.Printf("[computer-use/agent] vision LMM=%s", visionEntry.Name)

		// 옵션: grounding LMM 바인딩 확인. 있으면 click 좌표를 자연어 → 픽셀로 변환.
		// 없으면 vision LMM 이 직접 좌표를 출력하는 기존 동작으로 fallback.
		groundingEntry := s.loadGroundingLMM(r.Context())
		if groundingEntry != nil {
			log.Printf("[computer-use/agent] grounding LMM=%s (click_element 활성)", groundingEntry.Name)
			sendEvent(map[string]any{"type": "status", "text": "grounding LMM 사용: " + groundingEntry.Name})
		} else {
			log.Printf("[computer-use/agent] grounding LMM not bound (vision-direct coordinate fallback)")
		}

		const maxSteps = 15
		executed := 0
		lastScreenshotB64 := ""
		lastActionSignature := "" // e.g. "click:282,231" — 정확 일치 중복 감지용
		stagnationCount := 0      // 연속 '액션 실행했는데 화면 안 변함' 카운터

		// clickCluster — 최근 click 좌표 + 발생 step. Fuzzy dedup + 화면 마커 양쪽에 사용.
		// 커서 위치 + 몇 픽셀 어긋난 LLM 좌표가 동일 의도인데 sig 가 달라져 dedup 을 통과하는
		// 문제를 막기 위해, 최근 3개 클릭과 ±25px 이내면 같은 의도로 판정.
		var clickCluster []clickMarker
		const clickFuzzRadius = 25
		const clickClusterLimit = 3
		absInt := func(n int) int {
			if n < 0 {
				return -n
			}
			return n
		}
		isNearRecentClick := func(x, y int) (bool, int, int) {
			for _, c := range clickCluster {
				if absInt(c.X-x) < clickFuzzRadius && absInt(c.Y-y) < clickFuzzRadius {
					return true, c.X, c.Y
				}
			}
			return false, 0, 0
		}
		recordClick := func(x, y, step int) {
			clickCluster = append(clickCluster, clickMarker{X: x, Y: y, Step: step})
			if len(clickCluster) > clickClusterLimit {
				clickCluster = clickCluster[len(clickCluster)-clickClusterLimit:]
			}
		}

		type stepRecord struct {
			Step          int    `json:"step"`
			Observation   string `json:"observation"`
			Action        string `json:"action"`
			ScreenChanged bool   `json:"screen_changed"`
		}
		var stepHistory []stepRecord

		// 특정 라벨(OBSERVATION:, STATUS:, NEXT_ACTION:)의 값 라인만 추출.
		extractLine := func(thought, label string) string {
			upperLabel := strings.ToUpper(label)
			for _, line := range strings.Split(thought, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(strings.ToUpper(trimmed), upperLabel) {
					idx := strings.Index(trimmed, ":")
					if idx >= 0 {
						return strings.TrimSpace(trimmed[idx+1:])
					}
				}
			}
			return ""
		}

		// "click:282,231" 같은 서명 생성 — 동일 액션 반복 감지용.
		signatureOf := func(action map[string]any) string {
			t, _ := action["action"].(string)
			switch t {
			case "click", "double_click", "right_click":
				x, _ := action["x"].(float64)
				y, _ := action["y"].(float64)
				return fmt.Sprintf("%s:%d,%d", t, int(x), int(y))
			case "key":
				n, _ := action["name"].(string)
				return "key:" + strings.ToLower(n)
			case "type":
				txt, _ := action["text"].(string)
				if len(txt) > 20 {
					txt = txt[:20]
				}
				return "type:" + txt
			default:
				return t
			}
		}

		// Vision 응답의 NEXT_ACTION 라인을 파싱하여 단일 action map 반환.
		// 지원 포맷:
		//   key:NAME                            — 키보드 단축키
		//   type:TEXT                           — 텍스트 입력
		//   click:X,Y / double_click:X,Y        — 픽셀 좌표 직접 (vision-only fallback)
		//   click_element:DESCRIPTION           — 자연어 (grounding LMM 바인딩 시)
		//   double_click_element:DESCRIPTION    — 자연어 더블클릭
		//   wait / stop
		parseNextAction := func(thought string) (map[string]any, bool) {
			raw := extractLine(thought, "NEXT_ACTION:")
			if raw == "" {
				return nil, false
			}
			raw = strings.Trim(raw, "`\"' \t")
			lower := strings.ToLower(raw)
			switch {
			case strings.HasPrefix(lower, "stop"):
				return map[string]any{"action": "stop"}, true
			case strings.HasPrefix(lower, "wait"):
				return map[string]any{"action": "wait"}, true
			case strings.HasPrefix(lower, "key:"):
				name := strings.TrimSpace(raw[4:])
				if name == "" {
					return nil, false
				}
				return map[string]any{"action": "key", "name": name}, true
			case strings.HasPrefix(lower, "type:"):
				text := raw[5:]
				text = strings.TrimLeft(text, " ")
				if text == "" {
					return nil, false
				}
				return map[string]any{"action": "type", "text": text}, true
			case strings.HasPrefix(lower, "double_click_element:"):
				desc := strings.TrimSpace(raw[len("double_click_element:"):])
				if desc == "" {
					return nil, false
				}
				return map[string]any{"action": "click_element", "description": desc, "double": true}, true
			case strings.HasPrefix(lower, "click_element:"):
				desc := strings.TrimSpace(raw[len("click_element:"):])
				if desc == "" {
					return nil, false
				}
				return map[string]any{"action": "click_element", "description": desc, "double": false}, true
			case strings.HasPrefix(lower, "double_click:"), strings.HasPrefix(lower, "click:"):
				actionType := "click"
				coords := raw
				if strings.HasPrefix(lower, "double_click:") {
					actionType = "double_click"
					coords = raw[len("double_click:"):]
				} else {
					coords = raw[len("click:"):]
				}
				coords = strings.TrimSpace(coords)
				// 괄호 제거: (100, 200) → 100, 200
				coords = strings.Trim(coords, "()[]")
				parts := strings.Split(coords, ",")
				if len(parts) != 2 {
					return nil, false
				}
				x, errX := strconv.Atoi(strings.TrimSpace(parts[0]))
				y, errY := strconv.Atoi(strings.TrimSpace(parts[1]))
				if errX != nil || errY != nil {
					return nil, false
				}
				return map[string]any{"action": actionType, "x": float64(x), "y": float64(y)}, true
			}
			return nil, false
		}

		// 액션 타입별 UI 반응 대기 (사람이 눈으로 결과 확인하는 시간과 유사).
		waitFor := func(action map[string]any) time.Duration {
			t, _ := action["action"].(string)
			switch t {
			case "type":
				text, _ := action["text"].(string)
				// boan-computer-use TYPING_GROUP_SIZE=50, DELAY_MS=12 기준으로 여유있게
				return 800*time.Millisecond + time.Duration(len(text)*20)*time.Millisecond
			case "key":
				name, _ := action["name"].(string)
				lower := strings.ToLower(name)
				// dialog 유발 키 (저장/열기/확인) 는 넉넉히 대기
				if strings.Contains(lower, "ctrl+s") || strings.Contains(lower, "ctrl+o") ||
					strings.Contains(lower, "return") || strings.Contains(lower, "enter") {
					return 1500 * time.Millisecond
				}
				return 700 * time.Millisecond
			case "click", "double_click", "right_click":
				return 700 * time.Millisecond
			default:
				return 400 * time.Millisecond
			}
		}

		// ── 세션 파괴 위험 키 차단 (서버측 방어선) ─────────────────────────
		// RDP/Guacamole 세션에서 alt+F4 는 포커스에 따라 세션 로그아웃을 유발하고,
		// ctrl+alt+del / win+L / win+D 는 세션을 잠그거나 전환한다. 프롬프트가 금지하지만
		// LLM이 실수로 emit 할 수 있으므로 실행 직전에 한 번 더 필터링.
		isForbiddenKey := func(action map[string]any) (bool, string) {
			if t, _ := action["action"].(string); t != "key" {
				return false, ""
			}
			name, _ := action["name"].(string)
			lower := strings.ToLower(strings.ReplaceAll(name, " ", ""))
			forbiddenSubstrings := []string{
				"alt+f4", "alt-f4", "altf4",
				"ctrl+alt+delete", "ctrl+alt+del",
				"win+l", "meta+l", "super+l",
				"win+d", "meta+d", "super+d",
				"win+r", "meta+r",
			}
			for _, f := range forbiddenSubstrings {
				if strings.Contains(lower, f) {
					return true, name
				}
			}
			return false, ""
		}

		// ── 로그아웃/잠금 화면 감지 (관측값 기반) ───────────────────────────
		// vision LMM 의 OBSERVATION 이 로그아웃/잠금/로그인 화면을 암시하면
		// STATUS:COMPLETE 오판을 막고 즉시 중단. (스크린샷이 깨끗해 보인다고
		// 완료로 오인하는 경우 방지)
		looksBroken := func(observation string) bool {
			lower := strings.ToLower(observation)
			markers := []string{
				"logged out", "log out", "logout",
				"lock screen", "locked", "sign in", "sign-in", "signin",
				"ctrl+alt+del", "ctrl-alt-del",
				"press enter to log", "welcome screen",
				"로그아웃", "잠금", "로그인 화면",
			}
			for _, m := range markers {
				if strings.Contains(lower, m) {
					return true
				}
			}
			return false
		}

		// Vision 프롬프트 빌더 — 사람처럼 '브리핑 → 검증 → 결정' 흐름.
		// markers 는 스크린샷에 그려진 클릭 마커들과 1:1 매칭되는 메타정보 (LMM이 색상과 위치를 매칭).
		// groundingBound 가 true면 click_element:DESCRIPTION 형식을 권장 (좌표 부담 감소).
		buildVisionPrompt := func(scrW, scrH int, history []stepRecord, markers []clickMarker, stuck bool, groundingBound bool) string {
			var sb strings.Builder
			fmt.Fprintf(&sb, "You are a HUMAN operator (not an OCR engine) sitting in front of a Windows workstation\n")
			fmt.Fprintf(&sb, "(resolution: %dx%d pixels) connected over RDP/Guacamole. Think holistically: judge the\n", scrW, scrH)
			fmt.Fprintf(&sb, "overall situation, not just text on screen.\n\n")
			fmt.Fprintf(&sb, "USER'S OBJECTIVE (verbatim): %s\n\n", agentReq.Prompt)

			// ── 시각적 마커 안내 ────────────────────────────────────────
			if len(markers) > 0 {
				sb.WriteString("📍 VISUAL MARKERS ON THIS SCREENSHOT:\n")
				sb.WriteString("The screenshot you are viewing has been ANNOTATED with circles+crosses showing\n")
				sb.WriteString("where you (the agent) clicked in recent steps. The colors mean:\n")
				if len(markers) > 2 {
					sb.WriteString("  • DARK RED   = oldest click in this batch\n")
					sb.WriteString("  • RED        = middle click(s)\n")
					sb.WriteString("  • ORANGE     = your most recent click\n")
				} else if len(markers) == 2 {
					sb.WriteString("  • RED        = older click\n")
					sb.WriteString("  • ORANGE     = your most recent click\n")
				} else {
					sb.WriteString("  • ORANGE     = your most recent click\n")
				}
				sb.WriteString("Marker positions:\n")
				for i, m := range markers {
					tag := "older"
					if i == len(markers)-1 {
						tag = "MOST RECENT"
					}
					fmt.Fprintf(&sb, "  • step %d (%s): clicked at (%d, %d)\n", m.Step, tag, m.X, m.Y)
				}
				sb.WriteString("\nIf you see a marker but the target window is still open / nothing changed, that\n")
				sb.WriteString("click DID NOT WORK. Pick a CLEARLY DIFFERENT location (≥40 pixels away) or use a\n")
				sb.WriteString("completely different approach. Do NOT click within ~25 pixels of any existing marker.\n\n")
			}

			// ── 최근 액션 히스토리 ─────────────────────────────────────
			if len(history) > 0 {
				sb.WriteString("📜 Recent action log (most recent last):\n")
				for _, rec := range history {
					changed := "screen CHANGED"
					if !rec.ScreenChanged {
						changed = "no visible change"
					}
					obs := rec.Observation
					if len(obs) > 80 {
						obs = obs[:80] + "…"
					}
					fmt.Fprintf(&sb, "  step %d: %s → %s\n", rec.Step, rec.Action, changed)
					if obs != "" {
						fmt.Fprintf(&sb, "    └─ saw: %s\n", obs)
					}
				}
				sb.WriteString("\n")
			}

			if stuck {
				sb.WriteString("⚠ STUCK ALERT: recent click(s) produced no visible result. STOP repeating the\n")
				sb.WriteString("same area. Re-examine the screenshot, find the target with FRESH EYES, and either\n")
				sb.WriteString("(a) click somewhere clearly different, or (b) switch to a safe keyboard shortcut.\n\n")
			}

			// ── 결정 가이드 ───────────────────────────────────────────
			sb.WriteString("DECISION GUIDE (read carefully — priority order):\n")
			sb.WriteString("  1. ★★★ RESPECT THE USER'S EXACT METHOD. The user wrote the objective in their\n")
			sb.WriteString("     own words and may have specified HOW to perform each step. You MUST follow\n")
			sb.WriteString("     that method literally, even if another way would be faster or 'better'.\n")
			sb.WriteString("     Examples of method-specific phrasings and how to honor them:\n")
			sb.WriteString("       • '메모장 클릭해서 저장' / 'click notepad to save' →\n")
			sb.WriteString("            FIRST click on the Notepad window (to focus it), THEN save.\n")
			sb.WriteString("            Do NOT skip the click — even if Notepad already looks focused.\n")
			sb.WriteString("       • 'X 버튼 눌러서 닫아줘' / 'click the X to close' →\n")
			sb.WriteString("            MUST click the title-bar X button. NEVER use alt+F4 or ctrl+w.\n")
			sb.WriteString("       • '단축키로 저장' / 'save with keyboard shortcut' →\n")
			sb.WriteString("            Use ctrl+s. Don't open the File menu.\n")
			sb.WriteString("       • '메뉴에서 저장' / 'save from the menu' →\n")
			sb.WriteString("            Click the File menu, then click Save. Don't use ctrl+s.\n")
			sb.WriteString("     Re-read the objective at every step and check: am I honoring the method?\n")
			sb.WriteString("  2. Otherwise (when the user did NOT specify a method), prefer SAFE keyboard shortcuts:\n")
			sb.WriteString("     • Save: ctrl+s       • Confirm/OK: Return     • Cancel: Escape\n")
			sb.WriteString("     • Copy/Paste/Cut/Undo: ctrl+c / ctrl+v / ctrl+x / ctrl+z\n")
			sb.WriteString("     • Select all: ctrl+a  • New: ctrl+n          • Open: ctrl+o\n")
			sb.WriteString("     • Navigation: Tab, Return, BackSpace, arrows, F1..F12\n")
			sb.WriteString("  3. Type text (action: type:TEXT) when a text field is focused.\n")
			sb.WriteString("  4. Click a UI element (action: click:X,Y) at its CENTER pixel.\n\n")

			// ── 정확한 관찰 강제 (환각 방지) ──────────────────────────
			sb.WriteString("⚠ ANTI-HALLUCINATION CHECKLIST — do this BEFORE writing OBSERVATION:\n")
			sb.WriteString("  • Look at the ENTIRE screenshot pixel-by-pixel. Don't assume — see.\n")
			sb.WriteString("  • Are there any DIALOG WINDOWS visible? (Save dialog, error popup, file picker, etc.)\n")
			sb.WriteString("    A dialog box looks like a smaller window centered on screen with OK/Cancel buttons.\n")
			sb.WriteString("    If YES, the dialog is the FOCUSED element — interact with it first.\n")
			sb.WriteString("  • Which window has focus? Look at title bar darkness/highlight.\n")
			sb.WriteString("  • Is the document modified? (asterisk in title bar = unsaved)\n")
			sb.WriteString("  • Where exactly is each interactive element? Use real coordinates from the image.\n")
			sb.WriteString("  Then write OBSERVATION based on what you ACTUALLY SEE.\n\n")

			sb.WriteString("⛔ FORBIDDEN — these will be blocked server-side anyway:\n")
			sb.WriteString("  • alt+F4 (logs out the RDP session — use the title-bar X button click instead)\n")
			sb.WriteString("  • ctrl+alt+del, win+L, win+D, win+R\n\n")

			sb.WriteString("Closing a window safely (CRITICAL — read carefully):\n")
			sb.WriteString("  STEP A. FIRST identify the TARGET WINDOW's bounds in the screenshot.\n")
			sb.WriteString("          Find the window's title bar (the colored strip at the top with the title text).\n")
			sb.WriteString("          Note: the window may be MAXIMIZED (fills the screen) or WINDOWED (smaller, somewhere on desktop).\n")
			sb.WriteString("          Do NOT assume maximized — actually look at the pixels.\n")
			sb.WriteString("  STEP B. Find the X button on the RIGHT end of THAT title bar.\n")
			sb.WriteString("          The X button is the rightmost icon in the title bar, NOT the rightmost pixel of the screen.\n")
			sb.WriteString("          For a windowed app, the X button is INSIDE the window, not at the desktop edge.\n")
			sb.WriteString("  STEP C. Output click:X,Y at the CENTER of the X button you identified in STEP B.\n")
			sb.WriteString("  WARNING: If your previous X-click failed, the window is likely smaller/positioned differently than\n")
			sb.WriteString("           you assumed. Re-measure the title bar's actual right edge in the image. Don't guess.\n")
			sb.WriteString("  • If a save dialog appears, press Return (save) or Escape (cancel).\n\n")

			// ── 출력 포맷 ─────────────────────────────────────────────
			sb.WriteString("Respond in EXACTLY this format (plain text, no markdown, no code fences):\n")
			sb.WriteString("OBSERVATION: <2-3 sentences. Describe the WHOLE screen situation: which app is focused,\n")
			sb.WriteString("              are there dialogs/popups, what state is the document in. Be specific.>\n")
			sb.WriteString("VERIFICATION: <Looking at the markers (if any), did the previous click actually do what\n")
			sb.WriteString("               you expected? yes/no — explain in 1 sentence.>\n")
			sb.WriteString("STATUS: COMPLETE | INCOMPLETE\n")
			sb.WriteString("REASONING: <1 sentence on why the next action is chosen and whether it honors the user's method.>\n")
			if groundingBound {
				sb.WriteString("NEXT_ACTION: <one of: key:NAME | type:TEXT | click_element:DESCRIPTION | double_click_element:DESCRIPTION | wait | stop>\n\n")
				sb.WriteString("✨ A SPECIALIZED GROUNDING MODEL is available. For clicks, prefer click_element:DESCRIPTION\n")
				sb.WriteString("   instead of click:X,Y. The grounding model will convert the description to coordinates.\n")
				sb.WriteString("   DESCRIPTION should be a short, unambiguous noun phrase identifying the target element.\n")
				sb.WriteString("   Good: 'the X close button on the Notepad title bar'\n")
				sb.WriteString("   Good: 'the Save button in the file dialog'\n")
				sb.WriteString("   Bad : 'something near the top'  (too vague)\n")
				sb.WriteString("   Bad : 'click here' (no description of WHAT)\n")
				sb.WriteString("   You may still output click:X,Y if you are CERTAIN of pixel coordinates, but prefer click_element.\n\n")
			} else {
				sb.WriteString("NEXT_ACTION: <one of: key:NAME | type:TEXT | click:X,Y | double_click:X,Y | wait | stop>\n\n")
			}

			sb.WriteString("Hard rules:\n")
			sb.WriteString("  • STATUS = COMPLETE ONLY when the objective is VISIBLY achieved on screen.\n")
			sb.WriteString("    Not when the session logged out, not when only a lock screen is visible, not when\n")
			sb.WriteString("    the desktop merely 'looks clean'. Verify the target app actually closed/saved/etc.\n")
			sb.WriteString("  • If the screen is a logout / lock / Ctrl+Alt+Del screen, STATUS = INCOMPLETE and\n")
			sb.WriteString("    NEXT_ACTION = stop — the session is broken.\n")
			sb.WriteString("  • NEXT_ACTION must be a SINGLE action. No JSON, no list, no trailing explanation.\n")
			sb.WriteString("  • Coordinates are pixels, origin top-left. Use the CENTER of the target element.\n")
			sb.WriteString("  • Never click within ~25 px of an existing marker — that area already failed.\n")
			return sb.String()
		}

		for step := 0; step < maxSteps; step++ {
			// ── Step A: 스크린샷 캡처 (1회 retry 포함)
			sendEvent(map[string]any{"type": "status", "text": fmt.Sprintf("화면 캡처 중... (스텝 %d)", step+1)})
			screenshotB64 := ""
			var ssErr error
			var ssFrontendError string // frontend 가 명시적으로 보낸 error 메시지
			// 5번 retry — stale polling client 가 잡으면 짧은 backoff 후 active client 가 잡도록
			for attempt := 0; attempt < 5; attempt++ {
				var ssResult map[string]any
				ssResult, ssErr = queueAndWait(map[string]any{"action": "screenshot"})
				if ssErr != nil {
					log.Printf("[computer-use/agent] step=%d screenshot error attempt=%d: %v", step, attempt, ssErr)
					if attempt < 4 {
						time.Sleep(300 * time.Millisecond)
						continue
					}
					break
				}
				if v, _ := ssResult["image"].(string); v != "" {
					screenshotB64 = v
					ssFrontendError = ""
					break
				}
				if v, _ := ssResult["data"].(string); v != "" {
					screenshotB64 = v
					ssFrontendError = ""
					break
				}
				// frontend 가 error 키로 직접 메시지를 보낸 경우 캡쳐
				if errStr, ok := ssResult["error"].(string); ok && errStr != "" {
					ssFrontendError = errStr
				}
				keys := make([]string, 0, len(ssResult))
				for k := range ssResult {
					keys = append(keys, k)
				}
				// 진단 정보 전체 dump — 디버깅의 ground truth
				ssResultJSON, _ := json.Marshal(ssResult)
				log.Printf("[computer-use/agent] step=%d screenshot FAIL attempt=%d keys=%v frontendErr=%q FULL=%s", step, attempt, keys, ssFrontendError, string(ssResultJSON))
				if attempt < 4 {
					time.Sleep(300 * time.Millisecond)
				}
			}
			if ssErr != nil {
				log.Printf("[computer-use/agent] step=%d screenshot final error: %v — break loop", step, ssErr)
				sendEvent(map[string]any{"type": "error", "text": "스크린샷 실패: " + ssErr.Error()})
				break
			}
			if screenshotB64 == "" {
				log.Printf("[computer-use/agent] step=%d screenshot empty after retries (frontendErr=%q) — break loop", step, ssFrontendError)
				// frontend 에러 메시지를 사람이 알아볼 수 있는 한국어로 변환
				userMsg := "스크린샷 데이터 없음 (재시도 후)"
				if strings.Contains(strings.ToLower(ssFrontendError), "canvas") {
					userMsg = "❌ GCP 워크스테이션 화면을 캡처할 수 없습니다.\n" +
						"   → MyGCP 페이지가 브라우저에서 열려 있는지 확인하세요.\n" +
						"   → Guacamole iframe 이 Windows 바탕화면을 표시할 때까지 기다린 뒤 재시도하세요.\n" +
						"   → 만약 로그아웃/잠금 화면이 보인다면 MyGCP 페이지를 새로고침 후 재접속하세요.\n" +
						"   (frontend: " + ssFrontendError + ")"
				} else if ssFrontendError != "" {
					userMsg = "❌ 스크린샷 실패: " + ssFrontendError
				}
				sendEvent(map[string]any{"type": "error", "text": userMsg})
				go injectOpenClawMessage(fmt.Sprintf("[gcp_exec] %s : %s", agentReq.Prompt, userMsg))
				break
			}

			// ── 화면 변화 감지: 직전 스크린샷과 완전히 동일이면 '아무 일도 없었던 스텝'
			screenChanged := lastScreenshotB64 == "" || screenshotB64 != lastScreenshotB64
			// 직전 스텝이 실제로 액션을 실행했는데 화면이 안 변한 경우만 stagnation 카운트
			if !screenChanged && len(stepHistory) > 0 && stepHistory[len(stepHistory)-1].Action != "" {
				stagnationCount++
			} else if screenChanged {
				stagnationCount = 0
			}
			// 이전 스텝 레코드에 '실제로 화면이 바뀌었는지' 를 소급 기록
			if len(stepHistory) > 0 {
				stepHistory[len(stepHistory)-1].ScreenChanged = screenChanged
			}

			sendEvent(map[string]any{"type": "screenshot", "data": screenshotB64, "label": fmt.Sprintf("스텝 %d 화면", step+1)})
			lastScreenshotB64 = screenshotB64
			scrW, scrH := getImageDimensions(screenshotB64)
			log.Printf("[computer-use/agent] step=%d resolution=%dx%d changed=%v stagnation=%d", step, scrW, scrH, screenChanged, stagnationCount)

			// stagnation 3회면 조기 종료 — 인간도 3번 시도하고 안 되면 다른 방법을 찾음
			if stagnationCount >= 3 {
				log.Printf("[computer-use/agent] stagnation break at step %d", step)
				sendEvent(map[string]any{"type": "error", "text": "화면이 여러 스텝 동안 변하지 않아 중단합니다."})
				break
			}

			// ── Step B: Vision LMM 호출 (단일 호출로 observation + decision + action)
			sendEvent(map[string]any{"type": "status", "text": "Vision LMM이 화면을 분석 중..."})
			// 최근 3스텝만 프롬프트에 포함 (비대화 방지)
			recent := stepHistory
			if len(recent) > 3 {
				recent = recent[len(recent)-3:]
			}
			// stuck 조건: stagnation OR 클릭 클러스터에 누적이 있으면 (=같은 영역 반복)
			stuck := stagnationCount >= 1 || len(clickCluster) >= 2
			visionPrompt := buildVisionPrompt(scrW, scrH, recent, clickCluster, stuck, groundingEntry != nil)
			// ── 사람처럼 '저번에 어디 찍었지' 를 시각적으로 보여주기:
			// 원본 스크린샷에 클릭 마커를 그려서 vision LMM 에 전달.
			// 원본(screenshotB64)은 화면 변화 감지/챗 표시용으로 그대로 둠.
			annotatedB64 := annotateClicksOnScreenshot(screenshotB64, clickCluster)
			if len(clickCluster) > 0 {
				sendEvent(map[string]any{"type": "screenshot", "data": annotatedB64, "label": fmt.Sprintf("스텝 %d (클릭 마커 표시)", step+1)})
			}
			thought, vErr := s.forwardVisionLLM(r.Context(), visionEntry, annotatedB64, visionPrompt)
			if vErr != nil {
				log.Printf("[computer-use/agent] vision llm error: %v", vErr)
				sendEvent(map[string]any{"type": "error", "text": "Vision LMM 오류: " + vErr.Error()})
				break
			}
			log.Printf("[computer-use/agent] step=%d thought=%q", step, thought)
			sendEvent(map[string]any{"type": "thinking", "text": thought})

			observation := extractLine(thought, "OBSERVATION:")
			status := strings.ToUpper(extractLine(thought, "STATUS:"))

			// ── 세션 파괴 감지: 화면이 로그아웃/잠금 상태이면 즉시 중단.
			// vision 이 COMPLETE 라고 해도 무시한다 (오판 방지).
			if looksBroken(observation) {
				log.Printf("[computer-use/agent] broken session detected at step %d: %q", step, observation)
				sendEvent(map[string]any{"type": "error", "text": "세션이 로그아웃되었거나 잠금 상태입니다. (GCP 워크스테이션 재접속이 필요합니다)"})
				imgURL := makeChatScreenshotURL(screenshotB64)
				brokenMsg := fmt.Sprintf("[gcp_exec] %s : ❌ 세션 손상 — 로그아웃/잠금 화면 감지\n\n![](%s)", agentReq.Prompt, imgURL)
				go injectOpenClawMessage(brokenMsg)
				sendEvent(map[string]any{"type": "done", "actions_executed": executed})
				return
			}

			// ── Step C: 완료 판단
			if strings.Contains(status, "COMPLETE") && !strings.Contains(status, "INCOMPLETE") {
				log.Printf("[computer-use/agent] vision says COMPLETE at step %d", step)
				imgURL := makeChatScreenshotURL(screenshotB64)
				completedMsg := fmt.Sprintf("[gcp_exec] %s : 완료\n\n![](%s)", agentReq.Prompt, imgURL)
				go injectOpenClawMessage(completedMsg)
				sendEvent(map[string]any{"type": "done", "actions_executed": executed})
				return
			}

			// ── Step D: NEXT_ACTION 파싱
			action, ok := parseNextAction(thought)
			if !ok {
				log.Printf("[computer-use/agent] step=%d could not parse NEXT_ACTION", step)
				sendEvent(map[string]any{"type": "error", "text": "NEXT_ACTION 파싱 실패 — 다음 스텝에서 재시도"})
				stepHistory = append(stepHistory, stepRecord{
					Step: step + 1, Observation: observation, Action: "parse_failed", ScreenChanged: false,
				})
				continue
			}

			actionType, _ := action["action"].(string)
			if actionType == "stop" {
				log.Printf("[computer-use/agent] NEXT_ACTION=stop at step %d", step)
				break
			}
			if actionType == "wait" {
				sendEvent(map[string]any{"type": "status", "text": "UI 반응 대기 중..."})
				time.Sleep(1200 * time.Millisecond)
				stepHistory = append(stepHistory, stepRecord{
					Step: step + 1, Observation: observation, Action: "wait", ScreenChanged: false,
				})
				lastActionSignature = "wait"
				continue
			}

			// ── click_element → 좌표 변환 (grounding LMM 호출)
			// vision LMM 이 자연어 description 으로 답한 경우, grounding LMM 에 위임해서
			// (x, y) 를 받아낸다. grounding LMM 이 없으면 이 분기는 없음 (parseNextAction 단계에서
			// vision 프롬프트가 click_element 를 안 권장하므로 보통 click:X,Y 로 옴).
			if actionType == "click_element" {
				desc, _ := action["description"].(string)
				doubleClick, _ := action["double"].(bool)
				if groundingEntry == nil {
					log.Printf("[computer-use/agent] step=%d click_element received but no grounding LMM bound — dropping", step)
					sendEvent(map[string]any{"type": "error", "text": "click_element 사용 불가: grounding LMM 미바인딩"})
					stepHistory = append(stepHistory, stepRecord{
						Step: step + 1, Observation: observation, Action: "ERROR_no_grounding:" + desc, ScreenChanged: false,
					})
					continue
				}
				sendEvent(map[string]any{"type": "status", "text": fmt.Sprintf("🎯 grounding LMM 에 좌표 요청: %q", desc)})
				gx, gy, gErr := s.forwardGroundingLLM(r.Context(), groundingEntry, screenshotB64, desc, scrW, scrH)
				if gErr != nil {
					log.Printf("[computer-use/agent] step=%d grounding error desc=%q: %v", step, desc, gErr)
					sendEvent(map[string]any{"type": "error", "text": "grounding 실패: " + gErr.Error()})
					stepHistory = append(stepHistory, stepRecord{
						Step: step + 1, Observation: observation, Action: "GROUND_FAIL:" + desc, ScreenChanged: false,
					})
					continue
				}
				if gx < 0 || gy < 0 {
					log.Printf("[computer-use/agent] step=%d grounding returned not-found for %q", step, desc)
					sendEvent(map[string]any{"type": "status", "text": fmt.Sprintf("grounding: '%s' 를 화면에서 못 찾음", desc)})
					stepHistory = append(stepHistory, stepRecord{
						Step: step + 1, Observation: observation, Action: "GROUND_NOTFOUND:" + desc, ScreenChanged: false,
					})
					continue
				}
				log.Printf("[computer-use/agent] step=%d grounding %q → (%d, %d)", step, desc, gx, gy)
				sendEvent(map[string]any{"type": "status", "text": fmt.Sprintf("✓ grounding 결과: %s → (%d, %d)", desc, gx, gy)})
				// click_element 를 click / double_click 액션으로 변환 (이후 dedup/실행 경로 그대로 사용)
				if doubleClick {
					action = map[string]any{"action": "double_click", "x": float64(gx), "y": float64(gy)}
					actionType = "double_click"
				} else {
					action = map[string]any{"action": "click", "x": float64(gx), "y": float64(gy)}
					actionType = "click"
				}
			}

			// ── 세션 파괴 위험 키 필터: LLM이 실수로 alt+F4 등을 보내면 실행 전에 차단
			if blocked, keyName := isForbiddenKey(action); blocked {
				log.Printf("[computer-use/agent] step=%d FORBIDDEN key blocked: %s", step, keyName)
				sendEvent(map[string]any{"type": "status", "text": fmt.Sprintf("⛔ 금지 키 차단: %s — 창을 닫으려면 X 버튼 클릭을 사용하세요", keyName)})
				stepHistory = append(stepHistory, stepRecord{
					Step: step + 1, Observation: observation, Action: "BLOCKED_forbidden_key:" + keyName, ScreenChanged: false,
				})
				lastActionSignature = "key:" + strings.ToLower(keyName)
				continue
			}

			// ── Fuzzy click dedup: 새 click 이 최근 3개 클릭의 ±25px 안이면 동일 의도로 간주
			//    sig 단순 일치는 (282,231) 과 (280,229) 를 다른 액션으로 보지만,
			//    실제 LLM 의도는 동일하므로 좌표 거리로 판정한다.
			if actionType == "click" || actionType == "double_click" || actionType == "right_click" {
				xRaw, _ := action["x"].(float64)
				yRaw, _ := action["y"].(float64)
				cx, cy := int(xRaw), int(yRaw)
				if hit, prevX, prevY := isNearRecentClick(cx, cy); hit {
					log.Printf("[computer-use/agent] step=%d FUZZY click dedup blocked: (%d,%d) near (%d,%d)", step, cx, cy, prevX, prevY)
					sendEvent(map[string]any{"type": "status", "text": fmt.Sprintf("⛔ 같은 영역 클릭 반복 차단: (%d,%d) ~ 이전 (%d,%d)", cx, cy, prevX, prevY)})
					stepHistory = append(stepHistory, stepRecord{
						Step: step + 1, Observation: observation,
						Action:        fmt.Sprintf("BLOCKED_fuzzy_click:(%d,%d)~(%d,%d)", cx, cy, prevX, prevY),
						ScreenChanged: false,
					})
					stagnationCount++ // fuzzy 차단도 stagnation 으로 친다
					continue
				}
			}

			// ── 중복 액션 가드: 직전 서명과 같고 화면이 안 바뀌었다면 실행하지 않고 다음 스텝
			sig := signatureOf(action)
			if sig == lastActionSignature && !screenChanged && executed > 0 {
				log.Printf("[computer-use/agent] step=%d duplicate blocked sig=%s", step, sig)
				sendEvent(map[string]any{"type": "status", "text": "동일 액션 반복 감지 — 전략 변경 필요"})
				stepHistory = append(stepHistory, stepRecord{
					Step: step + 1, Observation: observation, Action: "BLOCKED_dup:" + sig, ScreenChanged: false,
				})
				continue
			}

			// ── Step E: 액션 실행 (stale client retry 지원)
			// 같은 액션을 최대 3번까지 큐에 다시 넣어서 active client 가 잡도록 한다.
			// 이유: stale polling client (iframe 없는 옛 탭) 가 액션을 빼가서 client null
			// 인 채로 {error: "stale polling client"} 반환할 수 있는데, 이때 active client
			// 가 다음 poll 에서 같은 액션을 받게 해야 함.
			actionJSON, _ := json.Marshal(action)
			log.Printf("[computer-use/agent] step=%d execute action=%s", step, actionJSON)
			sendEvent(map[string]any{"type": "action", "index": executed, "action": action})

			var result map[string]any
			var execErr error
			const maxActionRetries = 3
			for retry := 0; retry < maxActionRetries; retry++ {
				result, execErr = queueAndWait(action)
				if execErr != nil {
					break
				}
				// 결과 본문에 error 키가 있으면 stale client 가 잡은 것 — 재시도
				if errMsg, ok := result["error"].(string); ok && errMsg != "" {
					log.Printf("[computer-use/agent] step=%d action retry=%d frontend error: %s", step, retry, errMsg)
					sendEvent(map[string]any{"type": "status", "text": fmt.Sprintf("⚠ stale client 감지 (retry %d/%d)", retry+1, maxActionRetries)})
					time.Sleep(200 * time.Millisecond) // 짧은 backoff — 다음 poll 사이클 기다림
					continue
				}
				// success
				break
			}

			if execErr != nil {
				log.Printf("[computer-use/agent] step=%d action error: %v", step, execErr)
				sendEvent(map[string]any{"type": "action_result", "index": executed, "error": execErr.Error()})
				if execErr.Error() == "cancelled" {
					return
				}
				stepHistory = append(stepHistory, stepRecord{
					Step: step + 1, Observation: observation, Action: "error:" + execErr.Error(), ScreenChanged: false,
				})
				break
			}
			// 모든 retry 후에도 frontend error 면 fail-treat
			if errMsg, ok := result["error"].(string); ok && errMsg != "" {
				log.Printf("[computer-use/agent] step=%d action exhausted retries: %s", step, errMsg)
				sendEvent(map[string]any{"type": "action_result", "index": executed, "error": "stale client retries exhausted: " + errMsg})
				stepHistory = append(stepHistory, stepRecord{
					Step: step + 1, Observation: observation, Action: "STALE_RETRIES_EXHAUSTED", ScreenChanged: false,
				})
				break
			}

			sendEvent(map[string]any{"type": "action_result", "index": executed, "result": result})
			executed++
			actionDesc := formatActionDesc(action)
			go injectOpenClawMessage(fmt.Sprintf("[gcp_exec] %s : [%d] %s", agentReq.Prompt, executed, actionDesc))

			// 클릭이었다면 클러스터에 기록 (다음 스텝의 마커 + dedup 에 사용)
			if actionType == "click" || actionType == "double_click" || actionType == "right_click" {
				if xRaw, ok := action["x"].(float64); ok {
					if yRaw, ok := action["y"].(float64); ok {
						recordClick(int(xRaw), int(yRaw), step+1)
					}
				}
			}
			// 키/타이핑은 다른 의도이므로 클러스터 리셋 (이전 클릭 영역과 무관해진 판단)
			if actionType == "key" || actionType == "type" {
				clickCluster = nil
			}

			// ── Step F: 액션 타입에 맞춰 UI 반응 대기
			time.Sleep(waitFor(action))

			// ── Step G: 히스토리 기록 (screen_changed 는 다음 스텝 시작 시 소급)
			stepHistory = append(stepHistory, stepRecord{
				Step:          step + 1,
				Observation:   observation,
				Action:        string(actionJSON),
				ScreenChanged: false, // 다음 스텝이 업데이트
			})
			lastActionSignature = sig
		}

		// 종료 처리
		if executed == 0 && lastScreenshotB64 != "" {
			go injectOpenClawMessage(fmt.Sprintf("[gcp_exec] %s : 실행 실패 (액션 없음)", agentReq.Prompt))
		} else if executed > 0 && lastScreenshotB64 != "" {
			// STATUS:COMPLETE 없이 루프를 마친 경우 — 최종 화면을 챗에 전달
			imgURL := makeChatScreenshotURL(lastScreenshotB64)
			finalMsg := fmt.Sprintf("[gcp_exec] %s : 종료 (실행 %d회)\n\n![](%s)", agentReq.Prompt, executed, imgURL)
			go injectOpenClawMessage(finalMsg)
		}
		sendEvent(map[string]any{"type": "done", "actions_executed": executed})
	})

	// TEST 모드 전용 endpoint — cfg.TestMode 가 true 일 때만 등록.
	// (test_endpoints.go) — prod 에서는 TEST 환경변수 미설정 → 등록 자체 안 됨.
	if s.cfg.TestMode {
		s.registerTestEndpoints(mux)
	}

	srv := &http.Server{
		Addr:              s.cfg.AdminListen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = srv.ListenAndServe()
	}()
}

// clickMarker — annotateClicksOnScreenshot 에 넘기는 클릭 이력 항목.
// Label 은 마커 옆에 표시할 수는 없지만 (폰트 렌더링 생략) 색상으로 구분.
type clickMarker struct {
	X, Y int
	Step int  // 1-indexed step number (로그용)
	Note string // 현재 미사용 (향후 pass/fail 구분용)
}

// annotateClicksOnScreenshot — 스크린샷 위에 이전 클릭 위치를 시각화해서 반환.
// 사람이 '어디 찍었는지' 기억하듯 vision LMM 이 자기 클릭 이력을 한눈에 보게 함.
//   • 가장 오래된 클릭 → 어두운 빨강
//   • 중간 클릭 → 밝은 빨강
//   • 가장 최근 클릭 → 주황 (가장 눈에 띄게)
// PNG 디코딩/인코딩 실패 시 원본 base64 그대로 반환.
func annotateClicksOnScreenshot(b64 string, clicks []clickMarker) string {
	if len(clicks) == 0 {
		return b64
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return b64
	}
	src, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return b64
	}
	bounds := src.Bounds()
	rgba := image.NewRGBA(bounds)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			rgba.Set(x, y, src.At(x, y))
		}
	}
	white := color.RGBA{R: 255, G: 255, B: 255, A: 255}
	darkRed := color.RGBA{R: 180, G: 0, B: 0, A: 255}
	red := color.RGBA{R: 255, G: 40, B: 40, A: 255}
	orange := color.RGBA{R: 255, G: 160, B: 0, A: 255}
	n := len(clicks)
	for i, c := range clicks {
		fg := red
		if i == n-1 {
			fg = orange // 가장 최근
		} else if i == 0 && n > 2 {
			fg = darkRed // 가장 오래된 (3개 이상일 때만)
		}
		drawClickMarker(rgba, c.X, c.Y, fg, white)
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, rgba); err != nil {
		return b64
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// drawClickMarker — 이중 링 + 크로스(+) 를 그린다.
// 안쪽 흰색 링으로 어느 배경에서도 보이도록 대비 확보.
func drawClickMarker(img *image.RGBA, cx, cy int, fg, bg color.Color) {
	bounds := img.Bounds()
	setPx := func(x, y int, c color.Color) {
		if x < bounds.Min.X || x >= bounds.Max.X || y < bounds.Min.Y || y >= bounds.Max.Y {
			return
		}
		img.Set(x, y, c)
	}
	// 바깥 링 (radius 13~17, 색상)
	for dy := -17; dy <= 17; dy++ {
		for dx := -17; dx <= 17; dx++ {
			d := dx*dx + dy*dy
			if d >= 13*13 && d <= 17*17 {
				setPx(cx+dx, cy+dy, fg)
			}
		}
	}
	// 안쪽 흰색 링 (radius 10~12, 대비용)
	for dy := -12; dy <= 12; dy++ {
		for dx := -12; dx <= 12; dx++ {
			d := dx*dx + dy*dy
			if d >= 10*10 && d <= 12*12 {
				setPx(cx+dx, cy+dy, bg)
			}
		}
	}
	// 십자선 (+) — 길이 22, 두께 3
	for i := -11; i <= 11; i++ {
		for j := -1; j <= 1; j++ {
			setPx(cx+i, cy+j, fg)
			setPx(cx+j, cy+i, fg)
		}
	}
}

// getImageDimensions — base64 인코딩된 이미지의 너비/높이 반환 (실패 시 0, 0)
func getImageDimensions(b64 string) (int, int) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return 0, 0
	}
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return 0, 0
	}
	return cfg.Width, cfg.Height
}

// compressScreenshotForChat — PNG base64를 JPEG 소형 base64 로 압축 (legacy).
// 새 코드는 makeChatScreenshotURL 사용. fallback / 호환성 위해 유지.
func compressScreenshotForChat(b64 string) string {
	jpegBytes := compressScreenshotToJPEG(b64)
	if jpegBytes == nil {
		return b64
	}
	return base64.StdEncoding.EncodeToString(jpegBytes)
}

// compressScreenshotToJPEG — base64 PNG/JPEG 입력 → 작은 JPEG bytes 반환.
// 최대 너비 400px, quality 40. 디코딩 실패 시 nil.
func compressScreenshotToJPEG(b64 string) []byte {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil
	}
	src, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil
	}
	bounds := src.Bounds()
	srcW, srcH := bounds.Dx(), bounds.Dy()
	maxW := 400
	dstW, dstH := srcW, srcH
	if srcW > maxW {
		dstW = maxW
		dstH = srcH * maxW / srcW
	}
	dst := image.NewRGBA(image.Rect(0, 0, dstW, dstH))
	for y := 0; y < dstH; y++ {
		for x := 0; x < dstW; x++ {
			srcX := x * srcW / dstW
			srcY := y * srcH / dstH
			dst.Set(x, y, src.At(srcX, srcY))
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, dst, &jpeg.Options{Quality: 40}); err != nil {
		return nil
	}
	return buf.Bytes()
}

// makeChatScreenshotURL — base64 PNG → 압축된 JPEG 저장 → 짧은 markdown URL 반환.
// 인라인 base64 가 OpenClaw markdown 렌더러에서 깨지는 문제 회피.
//
// 사용:
//   url := makeChatScreenshotURL(screenshotB64)
//   if url != "" {
//     msg := fmt.Sprintf("[gcp_exec] %s : 완료\n\n![](%s)", prompt, url)
//   }
//
// URL 형식: http://localhost:19080/api/computer-use/screenshot/{id}.jpg
// (admin-console nginx → boan-proxy 로 reverse-proxy. 외부 노출 0.)
func makeChatScreenshotURL(b64 string) string {
	jpegBytes := compressScreenshotToJPEG(b64)
	if jpegBytes == nil {
		return ""
	}
	id := storeChatScreenshot(jpegBytes)
	return fmt.Sprintf("http://localhost:19080/api/computer-use/screenshot/%s.jpg", id)
}

// formatActionDesc — computer-use 액션을 사람이 읽기 쉬운 문자열로 변환
// formatGuardrailBlockMessage — 사용자가 차단 원인을 즉시 이해할 수 있는 메시지.
// 구성:
//   • 어떤 가드레일 계층(tier) 이 차단했는지 (G1 정규식 / G2 헌법 / G3 wiki / DLP / access 등)
//   • 구체 이유 (Reason 필드)
//   • 권장 조치 (tier별 hint)
//
// payload 는 원본 사용자 입력. 로그에만 잘라서 사용하고 본 메시지엔 포함하지 않음.
func formatGuardrailBlockMessage(resp InputGateResponse, _ string) string {
	tier := strings.TrimSpace(resp.Tier)
	reason := strings.TrimSpace(resp.Reason)
	action := strings.TrimSpace(resp.Action)

	tierLabel := tier
	tierDesc := ""
	hint := ""
	switch strings.ToUpper(tier) {
	case "G1":
		tierLabel = "G1 (정규식 패턴)"
		tierDesc = "입력 중 자격증명/토큰/비밀번호로 보이는 패턴이 감지되었습니다."
		hint = "• API 키 / 비밀번호 / 토큰을 직접 넣지 말고 자격증명 이름 ({{CREDENTIAL:이름}}) 을 사용하거나 Credentials 탭에서 먼저 등록하세요."
	case "G2":
		tierLabel = "G2 (헌법 + 보안 LLM)"
		tierDesc = "조직 헌법 기준 보안 LLM 이 입력 내용을 차단했습니다."
		hint = "• 사내 비밀/개인정보/민감 운영 명령을 포함하고 있지 않은지 확인하세요.\n• 일반 표현으로 다시 작성하거나, 필요하면 관리자에게 헌법 검토를 요청하세요."
	case "G3":
		tierLabel = "G3 (Wiki 적응형)"
		tierDesc = "조직 wiki 에 학습된 과거 사례 기준으로 차단했습니다."
		hint = "• 과거 차단 사례와 유사한 표현일 수 있습니다. Approvals 탭에서 승인 요청하면 관리자가 확인할 수 있습니다."
	case "DLP":
		tierLabel = "DLP 엔진"
		tierDesc = "데이터 유출 방지 엔진이 기밀 데이터 패턴을 감지했습니다."
		hint = "• 개인정보/계좌/주민번호/카드번호 등 민감 데이터가 포함되어 있는지 확인하세요."
	case "ACCESS":
		tierLabel = "Access Level (계정 권한)"
		tierDesc = "본 계정의 access_level 이 Deny 로 설정되어 낮은 보안레벨로의 정보 흐름이 차단됩니다."
		hint = "• 관리자에게 access_level 변경을 요청하거나, 허용된 대상으로만 요청을 보내세요."
	case "KEY", "CHORD", "CLIPBOARD":
		tierLabel = "입력 필터 (" + tier + ")"
		tierDesc = "해당 키/조합키/클립보드 작업이 허용 목록에 없어 차단되었습니다."
		hint = "• 허용된 키(Tab, Enter, Escape, F1~F12, 화살표) 또는 안전한 조합(Ctrl+C/V/X/A/Z/Y) 만 사용 가능합니다."
	default:
		if tierLabel == "" {
			tierLabel = "가드레일"
		}
		tierDesc = "입력이 현재 정책 기준으로 차단되었습니다."
		hint = "• 원인을 정확히 모르면 Observability 탭의 감사 로그에서 확인하거나 관리자에게 문의하세요."
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "🛡️ [가드레일 차단 — %s]\n\n", tierLabel)
	if tierDesc != "" {
		sb.WriteString(tierDesc)
		sb.WriteString("\n\n")
	}
	if reason != "" {
		fmt.Fprintf(&sb, "• 상세 사유: %s\n", reason)
	}
	if action != "" && action != "block" {
		fmt.Fprintf(&sb, "• 결정: %s\n", action)
	}
	if hint != "" {
		sb.WriteString("\n")
		sb.WriteString(hint)
		sb.WriteString("\n")
	}
	sb.WriteString("\n(이 메시지는 외부 LLM 에 전달되지 않았습니다.)")
	return sb.String()
}

func formatActionDesc(action map[string]any) string {
	actionType, _ := action["action"].(string)
	switch actionType {
	case "key":
		name, _ := action["name"].(string)
		return "key: " + name
	case "type":
		text, _ := action["text"].(string)
		if len([]rune(text)) > 30 {
			text = string([]rune(text)[:30]) + "…"
		}
		return "type: " + text
	case "click":
		x, _ := action["x"].(float64)
		y, _ := action["y"].(float64)
		return fmt.Sprintf("click (%d, %d)", int(x), int(y))
	case "double_click":
		x, _ := action["x"].(float64)
		y, _ := action["y"].(float64)
		return fmt.Sprintf("double_click (%d, %d)", int(x), int(y))
	case "screenshot":
		return "screenshot"
	default:
		b, _ := json.Marshal(action)
		return string(b)
	}
}

// injectOpenClawMessage — OpenClaw 채팅에 assistant 메시지를 chat.inject로 주입 (AI 트리거 없음)
func injectOpenClawMessage(msg string) {
	injectOpenClawMessageWithRole(msg, "assistant")
}

// injectOpenClawMessageWithRole — role("user"|"assistant")을 지정해 OpenClaw 채팅에 주입
func injectOpenClawMessageWithRole(msg, role string) {
	const openClawURL = "ws://boan-sandbox:18789/vcontrol-ui?token=boan-openclaw-local"
	idKey := hex.EncodeToString(func() []byte { b := make([]byte, 8); crand.Read(b); return b }())

	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	header := http.Header{"Origin": {"http://localhost:19080"}}
	conn, _, err := dialer.Dial(openClawURL, header)
	if err != nil {
		log.Printf("[openclaw-inject] dial failed: %v", err)
		return
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	type wsMsg struct {
		Type    string         `json:"type,omitempty"`
		Event   string         `json:"event,omitempty"`
		ID      string         `json:"id,omitempty"`
		Method  string         `json:"method,omitempty"`
		Ok      bool           `json:"ok,omitempty"`
		Params  map[string]any `json:"params,omitempty"`
		Payload map[string]any `json:"payload,omitempty"`
		Error   map[string]any `json:"error,omitempty"`
	}
	reqID := 1
	sendReq := func(method string, params map[string]any) error {
		id := fmt.Sprintf("%d", reqID)
		reqID++
		return conn.WriteJSON(map[string]any{
			"type": "req", "id": id, "method": method, "params": params,
		})
	}
	for {
		var m wsMsg
		if err := conn.ReadJSON(&m); err != nil {
			log.Printf("[openclaw-inject] read error: %v", err)
			return
		}
		switch {
		case m.Event == "connect.challenge":
			if err := sendReq("connect", map[string]any{
				"minProtocol": 3, "maxProtocol": 3,
				"client": map[string]any{
					"mode": "webchat", "instanceId": "boan-inject-" + idKey,
					"id": "openclaw-control-ui", "version": "1.0.0", "platform": "linux",
				},
				"role": "operator",
				"scopes": []string{"operator.admin", "chat", "session", "agent"},
				"caps":   []string{"tool-events"},
				"auth":   map[string]any{"token": "boan-openclaw-local"},
				"userAgent": "boan-proxy/1.0", "locale": "ko-KR",
			}); err != nil {
				log.Printf("[openclaw-inject] connect send error: %v", err)
				return
			}
		case m.Type == "res" && m.Ok && reqID == 2:
			// connect ok → sessions.patch (세션 없으면 생성, 있으면 no-op)
			if err := sendReq("sessions.patch", map[string]any{
				"key": "agent:main:main",
			}); err != nil {
				log.Printf("[openclaw-inject] sessions.patch send error: %v", err)
				return
			}
		case m.Type == "res" && reqID == 3:
			if !m.Ok {
				log.Printf("[openclaw-inject] sessions.patch failed: %v", m.Error)
				return
			}
			// patch ok → chat.inject
			injectParams := map[string]any{
				"sessionKey": "agent:main:main",
				"message":    msg,
			}
			if role != "" && role != "assistant" {
				injectParams["role"] = role
			}
			if err := sendReq("chat.inject", injectParams); err != nil {
				log.Printf("[openclaw-inject] inject send error: %v", err)
				return
			}
		case m.Type == "res" && reqID == 4:
			if !m.Ok {
				log.Printf("[openclaw-inject] chat.inject failed: %v", m.Error)
			} else {
				log.Printf("[openclaw-inject] ok: %s", msg)
			}
			return
		}
	}
}

// injectOpenClawChat — 실행 결과를 BoanClaw 채팅에 주입 (chat.inject, AI 트리거 없음)
func injectOpenClawChat(prompt string, actionsExecuted int, resultMsg string) {
	var msg string
	if resultMsg != "" {
		msg = fmt.Sprintf("[gcp_exec] %s : %s", prompt, resultMsg)
	} else if actionsExecuted > 0 {
		msg = fmt.Sprintf("[gcp_exec] %s : 실행 완료 — %d개 액션", prompt, actionsExecuted)
	} else {
		msg = fmt.Sprintf("[gcp_exec] %s : 실행 완료 (액션 없음)", prompt)
	}
	injectOpenClawMessage(msg)
}

// openClawChatSend — chat.send로 메시지 전달 (AI가 응답 생성, chat 모드 전용)
func openClawChatSend(msg, idempotencyKey string) (string, error) {
	const openClawURL = "ws://boan-sandbox:18789/vcontrol-ui?token=boan-openclaw-local"
	dialer := websocket.Dialer{HandshakeTimeout: 5 * time.Second}
	header := http.Header{"Origin": {"http://localhost:19080"}}
	conn, _, err := dialer.Dial(openClawURL, header)
	if err != nil {
		return "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(12 * time.Second))

	type wsMsg struct {
		Type    string         `json:"type,omitempty"`
		Event   string         `json:"event,omitempty"`
		ID      string         `json:"id,omitempty"`
		Ok      bool           `json:"ok,omitempty"`
		Payload map[string]any `json:"payload,omitempty"`
		Error   map[string]any `json:"error,omitempty"`
	}
	reqID := 1
	sendReq := func(method string, params map[string]any) error {
		id := fmt.Sprintf("%d", reqID)
		reqID++
		return conn.WriteJSON(map[string]any{
			"type": "req", "id": id, "method": method, "params": params,
		})
	}
	for {
		var m wsMsg
		if err := conn.ReadJSON(&m); err != nil {
			return "", fmt.Errorf("read: %w", err)
		}
		switch {
		case m.Event == "connect.challenge":
			if err := sendReq("connect", map[string]any{
				"minProtocol": 3, "maxProtocol": 3,
				"client": map[string]any{
					"mode": "webchat", "instanceId": "boan-chat-fwd-" + idempotencyKey,
					"id": "openclaw-control-ui", "version": "1.0.0", "platform": "linux",
				},
				"role": "operator",
				"scopes": []string{"operator.admin", "chat", "session", "agent"},
				"caps":   []string{"tool-events"},
				"auth":   map[string]any{"token": "boan-openclaw-local"},
				"userAgent": "boan-proxy/1.0", "locale": "ko-KR",
			}); err != nil {
				return "", fmt.Errorf("connect send: %w", err)
			}
		case m.Type == "res" && m.Ok && reqID == 2:
			if err := sendReq("chat.send", map[string]any{
				"sessionKey":     "agent:main:main",
				"message":        msg,
				"idempotencyKey": idempotencyKey,
			}); err != nil {
				return "", fmt.Errorf("chat.send: %w", err)
			}
		case m.Type == "res" && reqID == 3:
			if !m.Ok {
				errMsg := "unknown error"
				if m.Error != nil {
					if s, ok := m.Error["message"].(string); ok {
						errMsg = s
					}
				}
				return "", fmt.Errorf("chat.send failed: %s", errMsg)
			}
			runID, _ := m.Payload["runId"].(string)
			return runID, nil
		}
	}
}

func jsonMustMarshal(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func writeOpenAIStream(w http.ResponseWriter, resp map[string]any) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	model, _ := resp["model"].(string)
	id, _ := resp["id"].(string)
	created, _ := resp["created"].(int64)
	if created == 0 {
		switch v := resp["created"].(type) {
		case float64:
			created = int64(v)
		case int:
			created = int64(v)
		}
	}
	content := ""
	finishReason := "stop"
	if choices, ok := resp["choices"].([]any); ok && len(choices) > 0 {
		if choice, ok := choices[0].(map[string]any); ok {
			if message, ok := choice["message"].(map[string]any); ok {
				if text, ok := message["content"].(string); ok {
					content = text
				}
			}
			if fr, ok := choice["finish_reason"].(string); ok && fr != "" {
				finishReason = fr
			}
		}
	} else if choices, ok := resp["choices"].([]map[string]any); ok && len(choices) > 0 {
		if message, ok := choices[0]["message"].(map[string]any); ok {
			if text, ok := message["content"].(string); ok {
				content = text
			}
		}
		if fr, ok := choices[0]["finish_reason"].(string); ok && fr != "" {
			finishReason = fr
		}
	}

	flusher, _ := w.(http.Flusher)
	writeChunk := func(payload map[string]any) {
		buf, _ := json.Marshal(payload)
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(buf)
		_, _ = w.Write([]byte("\n\n"))
		if flusher != nil {
			flusher.Flush()
		}
	}

	writeChunk(map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []map[string]any{{
			"index": 0,
			"delta": map[string]any{"role": "assistant", "content": content},
		}},
	})
	writeChunk(map[string]any{
		"id":      id,
		"object":  "chat.completion.chunk",
		"created": created,
		"model":   model,
		"choices": []map[string]any{{
			"index":         0,
			"delta":         map[string]any{},
			"finish_reason": finishReason,
		}},
	})
	_, _ = w.Write([]byte("data: [DONE]\n\n"))
	if flusher != nil {
		flusher.Flush()
	}
}

func ensureMachineID(dataDir string) string {
	if strings.TrimSpace(dataDir) == "" {
		return randomMachineID()
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return randomMachineID()
	}
	path := filepath.Join(dataDir, "machine_id")
	if raw, err := os.ReadFile(path); err == nil {
		if id := strings.TrimSpace(string(raw)); id != "" {
			return id
		}
	}
	id := randomMachineID()
	if err := os.WriteFile(path, []byte(id), 0600); err != nil {
		return id
	}
	return id
}

func randomMachineID() string {
	buf := make([]byte, 16)
	if _, err := crand.Read(buf); err != nil {
		return fmt.Sprintf("machine-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	dlpStats := s.dlpEng.GetStats()
	auditTotal := uint64(0)
	auditBlocked := uint64(0)
	otelConnected := false
	if s.audit != nil {
		auditTotal = s.audit.TotalEvents()
		auditBlocked = s.audit.BlockedEvents()
		otelConnected = s.audit.IsConnected()
	}

	status := map[string]any{
		"status":    "ok",
		"org":       s.cfg.OrgID,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"dlp": map[string]any{
			"rules_loaded":    s.dlpRulesLoaded(),
			"total_inspected": dlpStats.TotalInspected,
			"total_blocked":   dlpStats.TotalBlocked,
			"total_redacted":  dlpStats.TotalRedacted,
			"total_allowed":   dlpStats.TotalAllowed,
		},
		"network_gate": map[string]any{
			"endpoint_count": s.gate.EndpointCount(),
			"last_fetch":     s.gate.LastFetch().Format(time.RFC3339),
			"allowed":        s.gate.StatsAllowed(),
			"blocked":        s.gate.StatsBlocked(),
		},
		"credentials": map[string]any{
			"count":  s.creds.CredentialCount(),
			"status": s.creds.StatusSummary(),
		},
		"routing": map[string]any{
			"to_security":  s.router.SecurityRouted(),
			"to_usability": s.router.UsabilityRouted(),
		},
		"tls": map[string]any{
			"cache_size": s.ca.CacheSize(),
		},
		"audit": map[string]any{
			"otel_connected": otelConnected,
			"total_events":   auditTotal,
			"blocked_events": auditBlocked,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status) //nolint:errcheck
}

func (s *Server) handleDLPStatus(w http.ResponseWriter, _ *http.Request) {
	stats := s.dlpEng.GetStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"rules_loaded":    s.dlpRulesLoaded(),
		"total_inspected": stats.TotalInspected,
		"total_blocked":   stats.TotalBlocked,
		"total_redacted":  stats.TotalRedacted,
		"total_allowed":   stats.TotalAllowed,
	})
}

func (s *Server) handleGateStatus(w http.ResponseWriter, _ *http.Request) {
	count := s.gate.EndpointCount()
	if count == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"status":         "no_policy",
			"endpoint_count": 0,
		})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"status":         "ok",
		"endpoint_count": count,
		"last_fetch":     s.gate.LastFetch().Format(time.RFC3339),
	})
}

func (s *Server) handleCredentialStatus(w http.ResponseWriter, _ *http.Request) {
	summary := s.creds.StatusSummary()
	allOK := true
	for _, st := range summary {
		if st != "ok" {
			allOK = false
			break
		}
	}
	code := http.StatusOK
	if !allOK {
		code = http.StatusServiceUnavailable
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"count":  len(summary),
		"all_ok": allOK,
		"status": summary,
	})
}

func (s *Server) handleRoutingStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"to_security":  s.router.SecurityRouted(),
		"to_usability": s.router.UsabilityRouted(),
	})
}

func (s *Server) dlpRulesLoaded() int {
	return s.dlpEng.RulesCount()
}

// applyConstitutionDiff — unified diff에서 + 줄만 추출하여 새 헌법 텍스트 생성.
// 완전한 diff 파서가 아닌 간이 처리: diff가 전체 교체 형태면 + 줄이 새 헌법.
func applyConstitutionDiff(diff string) string {
	lines := strings.Split(diff, "\n")
	var result []string
	for _, l := range lines {
		if strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++") {
			result = append(result, strings.TrimPrefix(l, "+"))
		} else if !strings.HasPrefix(l, "-") && !strings.HasPrefix(l, "---") && !strings.HasPrefix(l, "@@") {
			result = append(result, l)
		}
	}
	text := strings.TrimSpace(strings.Join(result, "\n"))
	if text == "" {
		return ""
	}
	return text
}

