package proxy

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/audit"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/auth"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/orgserver"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/orgstore"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/wikiskills"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/roles"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/userstore"
)

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

// ── Golden Image job tracking ─────────────────────────────────────────
// in-memory: 서버 재시작 시 초기화됨 (중단된 job 은 수동 확인 필요).
type goldImageJob struct {
	ID         string    `json:"id"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Status     string    `json:"status"` // running | success | failed
	Stage      string    `json:"stage"`  // 현재 단계 hint
	ImageName  string    `json:"image_name,omitempty"`
	ImageURI   string    `json:"image_uri,omitempty"`
	Error      string    `json:"error,omitempty"`
}

var (
	goldImageJobMu sync.Mutex
	goldImageJobs  = map[string]*goldImageJob{}
)

func recordGoldImageJob(j *goldImageJob) {
	goldImageJobMu.Lock()
	defer goldImageJobMu.Unlock()
	goldImageJobs[j.ID] = j
	// simple GC — 24 시간 지난 job 정리.
	cutoff := time.Now().Add(-24 * time.Hour)
	for id, other := range goldImageJobs {
		if !other.FinishedAt.IsZero() && other.FinishedAt.Before(cutoff) {
			delete(goldImageJobs, id)
		}
	}
}

func updateGoldImageJob(id string, mutator func(*goldImageJob)) {
	goldImageJobMu.Lock()
	defer goldImageJobMu.Unlock()
	if j := goldImageJobs[id]; j != nil {
		mutator(j)
	}
}

func getGoldImageJob(id string) *goldImageJob {
	goldImageJobMu.Lock()
	defer goldImageJobMu.Unlock()
	if j := goldImageJobs[id]; j != nil {
		// copy to avoid concurrent mutation by caller
		copy := *j
		return &copy
	}
	return nil
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
		return s.orgs.ClientFor(orgID).SyncUser(orgID, strings.TrimSpace(strings.ToLower(email)), name, role, provider, status, machineID, machineName)
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

	// clearBoundUserIfMatches — 사용자 삭제 시 호출. bound_user 파일 내용이
	// 삭제되는 이메일과 일치하면 파일 제거 → 다음 사용자가 로그인/등록 가능.
	clearBoundUserIfMatches := func(email string) {
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

	if bound := inferBoundUser(); bound != "" && readBoundUser() == bound {
		bindUserToPC(bound)
	}

	deviceLockedMessage := "이 PC는 이미 다른 사용자 계정에 연결되어 있습니다. 소유자 계정은 로그인할 수 있지만, 사용자 계정은 한 PC당 1개만 사용할 수 있습니다."

	// 설치 바인딩 (TOFU: Trust On First Use).
	// 이전엔 client IP 로 바인딩했으나 Docker 의 userland-proxy 가 source IP 를 bridge gateway 로
	// 재작성해서 모든 사용자가 172.x 로 나오는 문제가 있었음. 대신 설치 시 자동 생성되는
	// /data/users/machine_id (32-hex 랜덤) 를 바인딩 키로 사용 — Docker NAT 와 무관한 안정적 식별자.
	// 관리자 리셋: POST /org/{id}/v1/users/reset-ip

	// checkLoginIP — GCP org-server 에 TOFU 바인딩 검증 요청.
	// 바인딩 값은 이 proxy 의 machine_id (설치 고유 ID).
	// fail-closed: org-server 불통 시 로그인 차단.
	checkLoginIP := func(email, orgID string, r *http.Request) (bool, string) {
		_ = r // 이전 signature 유지 (호출부 수정 최소화)
		targetOrg := orgID
		if targetOrg == "" {
			targetOrg = defaultOrgID
		}
		allowed, reason, err := s.orgs.ClientFor(targetOrg).CheckLoginIP(targetOrg, email, machineID)
		if err != nil {
			log.Printf("[login-binding] org-server error for %s from install %s: %v", email, machineID, err)
			return false, "조직 서버 연결 실패 — 관리자에게 문의하세요."
		}
		if !allowed {
			log.Printf("[login-binding] blocked %s from install %s (reason: %s)", email, machineID, reason)
			if reason == "ip_mismatch" {
				return false, "다른 PC 에서만 로그인 가능 — 본 PC 는 등록된 설치가 아닙니다."
			}
			if reason == "user_not_found" {
				return false, "" // caller 가 별도 처리 (remote register 등)
			}
			return false, "로그인이 허용되지 않았습니다."
		}
		if reason == "captured" {
			log.Printf("[login-binding] captured install %s for %s (first login — TOFU)", machineID, email)
		}
		return true, ""
	}

	resolveLoginAccess := func(email, name, provider, wantOrgID string, r *http.Request) (roles.Role, string, bool, string, error) {
		email = strings.TrimSpace(strings.ToLower(email))
		orgID := defaultOrgID
		if wantOrgID != "" {
			orgID = wantOrgID
		}

		// 권한은 **해당 조직의 policy-server** 가 결정.
		// 로컬 env BOAN_OWNER_EMAIL 은 "이 호스트의 로컬 관리자" 의미로만 쓰이고, 조직 owner 와 무관.
		// key = (email, org_id). 한 이메일이 여러 조직에서 다른 역할을 가질 수 있음.
		client := s.orgs.ClientFor(orgID)

		// 먼저 org 에서 이 user 의 role 조회 — owner 는 device lock 도 우회해야 함.
		var orgRole roles.Role
		var orgStatus userstore.Status
		var foundInOrg bool
		if users, err := client.ListUsers(orgID); err == nil {
			for _, u := range users {
				if !strings.EqualFold(u.Email, email) {
					continue
				}
				r := roles.Normalize(roles.Role(u.Role))
				if r != roles.Owner {
					r = roles.User
				}
				orgRole = r
				orgStatus = userstore.StatusPending
				if u.Status == string(userstore.StatusApproved) {
					orgStatus = userstore.StatusApproved
				}
				foundInOrg = true
				break
			}
		}

		// owner 가 아닌 일반 user 의 경우 device lock 적용 (한 PC 당 1명).
		// owner 는 device lock 우회 (admin 용도).
		if orgRole != roles.Owner {
			if bound := readBoundUser(); bound != "" && bound != email {
				return roles.User, orgID, false, deviceLockedMessage, nil
			}
		}

		if foundInOrg {
			syncLocalUser(email, orgID, string(orgRole), orgStatus)
			if orgStatus == userstore.StatusApproved {
				if orgRole != roles.Owner {
					bindUserToPC(email)
				}
				return orgRole, orgID, true, "", nil
			}
			return roles.User, orgID, false, requestApprovalMessage, nil
		}

		// 해당 조직에 처음 들어오는 사람 — pending user 로 신청 접수.
		// (조직 owner 는 deploy 시점에 seed 되므로 여기서 자동 owner 승격 없음.)
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
		entries, err := s.orgs.ClientFor(defaultOrgID).GetTrainingLog(defaultOrgID)
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
		// Fetch wiki pages — try local policy-server first (wiki compiled locally),
		// fall back to GCP orgserver. Use no-proxy client to avoid HTTP_PROXY.
		noProxyFetch := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return nil, nil }}}
		localWikiURL := fmt.Sprintf("http://boan-policy-server:8081/org/%s/v1/wiki/pages", defaultOrgID)
		var wikiPages []map[string]any
		if resp, err := noProxyFetch.Get(localWikiURL); err == nil {
			defer resp.Body.Close()
			json.NewDecoder(resp.Body).Decode(&wikiPages)
		}
		if len(wikiPages) == 0 {
			wikiPages, _ = s.orgs.ClientFor(defaultOrgID).GetWikiPages(defaultOrgID)
		}
		if wikiPages == nil {
			wikiPages = []map[string]any{}
		}
		localIndexURL := fmt.Sprintf("http://boan-policy-server:8081/org/%s/v1/wiki", defaultOrgID)
		var wikiIndex map[string]any
		if resp, err := noProxyFetch.Get(localIndexURL); err == nil {
			defer resp.Body.Close()
			json.NewDecoder(resp.Body).Decode(&wikiIndex)
		}
		if wikiIndex == nil {
			wikiIndex, _ = s.orgs.ClientFor(defaultOrgID).GetWikiIndex(defaultOrgID)
		}
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
		// Get G3 LLM from registry for wiki compilation
		var g3LLMURL, g3LLMModel string
		if s.cfg.LLMRegistryURL != "" {
			regURL := strings.TrimRight(s.cfg.LLMRegistryURL, "/") + "/llm/list"
			if resp, err := http.Get(regURL); err == nil {
				defer resp.Body.Close()
				var llms []struct {
					Name     string   `json:"name"`
					Endpoint string   `json:"endpoint"`
					Roles    []string `json:"roles"`
					Healthy  bool     `json:"healthy"`
				}
				if json.NewDecoder(resp.Body).Decode(&llms) == nil {
					for _, l := range llms {
						for _, role := range l.Roles {
							if role == "g3" && l.Endpoint != "" {
								g3LLMURL = l.Endpoint + "/v1/chat/completions"
								g3LLMModel = l.Name
								break
							}
						}
						if g3LLMURL != "" { break }
					}
				}
			}
		}
		// Wiki compile needs local LLM access (ollama) → use local policy server, not GCP
		// Use a no-proxy client to avoid HTTP_PROXY environment variable routing through boan-proxy
		noProxyClient := &http.Client{Transport: &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return nil, nil }}}
		localPolicyURL := "http://boan-policy-server:8081"
		compileURL := fmt.Sprintf("%s/org/%s/v1/wiki/compile", localPolicyURL, defaultOrgID)
		compileBody, _ := json.Marshal(map[string]string{"llm_url": g3LLMURL, "llm_model": g3LLMModel})
		compileReq, _ := http.NewRequest(http.MethodPost, compileURL, bytes.NewReader(compileBody))
		compileReq.Header.Set("Content-Type", "application/json")
		compileResp, compileErr := noProxyClient.Do(compileReq)
		if compileErr != nil {
			// Fallback to orgServer (GCP)
			compileErr = s.orgs.ClientFor(defaultOrgID).CompileWikiWithLLM(defaultOrgID, g3LLMURL, g3LLMModel)
		} else {
			compileResp.Body.Close()
			if compileResp.StatusCode >= 300 {
				compileErr = fmt.Errorf("local policy server returned %d", compileResp.StatusCode)
			}
		}
		if err := compileErr; err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		// After successful compile, read proposals and create approval requests
		proposalCount := 0
		localPagesURL := fmt.Sprintf("http://boan-policy-server:8081/org/%s/v1/wiki/pages", defaultOrgID)
		if pResp, err := noProxyClient.Get(localPagesURL); err == nil {
			defer pResp.Body.Close()
			var pages []struct {
				Path    string `json:"path"`
				Content string `json:"content"`
			}
			if json.NewDecoder(pResp.Body).Decode(&pages) == nil {
				for _, pg := range pages {
					if !strings.HasPrefix(pg.Path, "proposals/") || strings.TrimSpace(pg.Content) == "" {
						continue
					}
					cmd := "g1-amendment:review"
					if strings.Contains(pg.Path, "g2") {
						cmd = "constitution-amendment:review"
					}
					id := fmt.Sprintf("apr-%s", randomMachineID()[:12])
					approvalsMu.Lock()
					// Avoid duplicate: check if same content already pending
					duplicate := false
					for _, a := range approvalsStore {
						if ac, _ := a["command"].(string); ac == cmd {
							if as, _ := a["status"].(string); as == "pending" {
								duplicate = true
								break
							}
						}
					}
					if !duplicate {
						approvalsStore = append(approvalsStore, map[string]any{
							"id":          id,
							"sessionId":   "wiki-compile",
							"command":     cmd,
							"args":        []string{"diff=" + pg.Content, "reasoning=G3 wiki compilation analysis"},
							"requester":   "wiki-guardrail",
							"org_id":      defaultOrgID,
							"requestedAt": time.Now().UTC().Format(time.RFC3339),
							"status":      "pending",
						})
						proposalCount++
					}
					approvalsMu.Unlock()
				}
			}
		}

		json.NewEncoder(w).Encode(map[string]any{
			"status":         "ok",
			"llm_used":       g3LLMModel,
			"llm_url":        g3LLMURL,
			"proposals_queued": proposalCount,
		})
	})

	// ── Wiki pages (all pages with content) ──
	mux.HandleFunc("/api/admin/wiki/pages", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) { return }
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		pages, err := s.orgs.ClientFor(defaultOrgID).GetWikiPages(defaultOrgID)
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
		// TOFU IP 검증 (GCP 중앙)
		if ok, msg := checkLoginIP(userInfo.Email, gcpOrgID, r); !ok && msg != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"error": msg})
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
		// TOFU IP 검증 (GCP 중앙)
		if ok, msg := checkLoginIP(body.Email, orgID, r); !ok && msg != "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"error": msg})
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
				g1Patterns = append(g1Patterns, G1PatternRule{Pattern: r.Pattern, Replacement: r.Replacement, Mode: r.Mode})
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
			// Step 1: credential gate — secret → {{CREDENTIAL:name}} 치환 + unknown redact.
			gateResult := s.applyCredentialGate(ctx, orgID, text, func(keys []string, previews []string, fps []string) string {
				return createCredentialGateApproval(orgID, keys, previews, fps)
			})
			// Step 2: substituted text 로 input gate 재평가 — G1 block/redact +
			// G2 (헌법) + G3 (wiki) + DLP. PostCredentialSubstitute 로 credential
			// 패턴만 skip (이미 치환 완료).
			reReq := req
			reReq.Text = gateResult.Prompt
			reReq.PostCredentialSubstitute = true
			resp = evaluateInputGateWithLocal(ctx, s.dlpEng, s.guardrail, s.evaluateGuardrailLocal, orgID, reReq,
				func(reason string, r InputGateRequest) string {
					return createInputGateApproval(requester, orgID, reason, r)
				},
			)
			resp.NormalizedText = gateResult.Prompt
			if gateResult.HITLRequired && resp.ApprovalID == "" {
				resp.ApprovalID = gateResult.ApprovalID
			}
			// 최종 reason 에 credential gate 가 개입했음 표기 (tier 는 재평가 결과 유지).
			if resp.Reason == "" {
				resp.Reason = "credential gate passed → downstream allow"
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

	// POST /api/admin/workstation/image — owner 전용.
	// owner 의 현재 VM 을 GCP Custom Image 로 스냅샷 → org settings 의
	// golden_image_uri 에 저장 → 이후 신규 사용자 VM 은 이 이미지로 프로비저닝.
	// 요구: 소유자 권한, owner 본인의 workstation 존재.
	// 흐름: STOP → image 생성 (최대 20분) → START → settings 저장.
	// 전용 go-routine 으로 실행해서 HTTP 응답은 즉시 ACK (long poll 방지).
	mux.HandleFunc("/api/admin/workstation/image", func(w http.ResponseWriter, r *http.Request) {
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
		if u, err := s.users.Get(sess.Email); err != nil || u == nil || strings.ToLower(u.Role) != "owner" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]any{"error": "owner role required"})
			return
		}
		current, _ := s.users.Workstation(sess.Email)
		if current == nil || current.InstanceID == "" {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]any{"error": "owner has no provisioned workstation"})
			return
		}
		var body struct {
			Name        string `json:"name,omitempty"`
			Description string `json:"description,omitempty"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Description == "" {
			body.Description = fmt.Sprintf("BoanClaw golden image captured from %s at %s", current.InstanceID, time.Now().UTC().Format(time.RFC3339))
		}

		// ACK 즉시 반환 — 실제 imaging 은 background.
		jobID := fmt.Sprintf("goldimg-%d", time.Now().UnixNano())
		recordGoldImageJob(&goldImageJob{
			ID:        jobID,
			StartedAt: time.Now().UTC(),
			Status:    "running",
			Stage:     "시작 중 — VM 정지 요청",
			ImageName: body.Name,
		})
		json.NewEncoder(w).Encode(map[string]any{
			"status":   "started",
			"job_id":   jobID,
			"hint":     "골든 이미지 생성 중. 약 5-15분 소요 — GET /api/admin/workstation/image/status?job_id=<id> 로 진행 상황 폴링 가능.",
			"poll_url": "/api/admin/workstation/image/status?job_id=" + jobID,
		})

		ws := &userstore.Workstation{
			Provider:   current.Provider,
			Platform:   current.Platform,
			InstanceID: current.InstanceID,
			Region:     current.Region,
		}
		orgID := sess.OrgID
		email := sess.Email
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			log.Printf("[golden-image] start: orgID=%s email=%s instance=%s job=%s", orgID, email, ws.InstanceID, jobID)

			// 시간대별 대략적인 stage 추정을 위한 goroutine — 실제 진행 정보가
			// 없으니 경과 시간 기반으로 표시만 변경. CaptureGoldenImage 는
			// refactor 하지 않음 (STOP 3분 → create image 5-15분 → START 3분).
			stageTicker := time.NewTicker(15 * time.Second)
			defer stageTicker.Stop()
			done := make(chan struct{})
			go func() {
				for {
					select {
					case <-done:
						return
					case <-stageTicker.C:
						updateGoldImageJob(jobID, func(j *goldImageJob) {
							if j.Status != "running" {
								return
							}
							elapsed := time.Since(j.StartedAt).Seconds()
							switch {
							case elapsed < 60:
								j.Stage = "1/4 VM 정지 중 (TERMINATED 대기)"
							case elapsed < 180:
								j.Stage = "2/4 이미지 생성 요청됨 (GCP Custom Image 생성 시작)"
							case elapsed < 600:
								j.Stage = "3/4 이미지 빌드 중 (Windows boot disk 복제 — 5-10분 소요)"
							default:
								j.Stage = "4/4 이미지 READY 대기 + VM 재시작 준비"
							}
						})
					}
				}
			}()

			imageURI, err := s.workstations.CaptureGoldenImage(ctx, ws, body.Name, body.Description)
			close(done)
			finish := time.Now().UTC()
			if err != nil {
				log.Printf("[golden-image] FAILED orgID=%s job=%s: %v", orgID, jobID, err)
				updateGoldImageJob(jobID, func(j *goldImageJob) {
					j.Status = "failed"
					j.Stage = "실패"
					j.Error = err.Error()
					j.FinishedAt = finish
				})
				return
			}
			log.Printf("[golden-image] SUCCESS orgID=%s job=%s imageURI=%s", orgID, jobID, imageURI)
			// org settings 에 저장
			if s.orgSettings != nil {
				_, _ = s.orgSettings.Patch(orgID, nil, map[string]interface{}{
					"golden_image_uri":       imageURI,
					"golden_image_captured_at": time.Now().UTC().Format(time.RFC3339),
					"golden_image_source_instance": ws.InstanceID,
				})
			}
			updateGoldImageJob(jobID, func(j *goldImageJob) {
				j.Status = "success"
				j.Stage = "완료"
				j.ImageURI = imageURI
				j.FinishedAt = finish
			})
		}()
	})

	// GET /api/admin/workstation/image/status?job_id=<id> — 골든 이미지 생성 진행상황.
	mux.HandleFunc("/api/admin/workstation/image/status", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) { return }
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.NotFound(w, r); return
		}
		jobID := r.URL.Query().Get("job_id")
		if jobID == "" {
			http.Error(w, `{"error":"job_id required"}`, http.StatusBadRequest); return
		}
		j := getGoldImageJob(jobID)
		if j == nil {
			http.Error(w, `{"error":"job not found (서버 재시작 시 메모리에서 사라짐)"}`, http.StatusNotFound); return
		}
		elapsed := int(time.Since(j.StartedAt).Seconds())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":          j.ID,
			"status":      j.Status,
			"stage":       j.Stage,
			"started_at":  j.StartedAt.Format(time.RFC3339),
			"finished_at": func() any {
				if j.FinishedAt.IsZero() {
					return nil
				}
				return j.FinishedAt.Format(time.RFC3339)
			}(),
			"elapsed_seconds": elapsed,
			"image_name":      j.ImageName,
			"image_uri":       j.ImageURI,
			"error":           j.Error,
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
				body.G1Patterns = append(body.G1Patterns, G1PatternRule{Pattern: r.Pattern, Replacement: r.Replacement, Mode: r.Mode})
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
		// Credential gate: secret → {{CREDENTIAL:name}} 치환 + unknown redact.
		// 통과 후 substituted text 를 가지고 G1 block/redact + G2 + G3 + DLP 재평가.
		// 체인: Credential → G1 → G2 → G3 → DLP.
		if resp.Action == "credential_required" && body.Text != "" {
			gateResult := s.applyCredentialGate(r.Context(), sess.OrgID, body.Text, func(keys []string, previews []string, fps []string) string {
				return createCredentialGateApproval(sess.OrgID, keys, previews, fps)
			})
			reBody := body
			reBody.Text = gateResult.Prompt
			reBody.PostCredentialSubstitute = true
			resp = evaluateInputGateWithLocal(
				r.Context(),
				s.dlpEng,
				s.guardrail,
				s.evaluateGuardrailLocal,
				sess.OrgID,
				reBody,
				func(reason string, req InputGateRequest) string {
					return createInputGateApproval(sess.Email, sess.OrgID, reason, req)
				},
			)
			resp.NormalizedText = gateResult.Prompt
			if gateResult.HITLRequired && resp.ApprovalID == "" {
				resp.ApprovalID = gateResult.ApprovalID
			}
			if resp.Reason == "" {
				resp.Reason = "credential gate passed → downstream allow"
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

		// TOFU IP 검증 (GCP 중앙)
		if ok, msg := checkLoginIP(body.Email, orgID, r); !ok && msg != "" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": msg})
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

	// GET /api/orgs — public list (login screen dropdown).
	// Returns [{org_id, label, url, is_active}] with token redacted.
	mux.HandleFunc("/api/orgs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		entries := s.orgs.PublicList()
		active := s.orgs.ActiveID()
		out := make([]map[string]any, 0, len(entries))
		for _, e := range entries {
			label := e.Label
			if label == "" {
				label = e.OrgID
			}
			out = append(out, map[string]any{
				"org_id":    e.OrgID,
				"label":     label,
				"url":       e.URL,
				"is_active": e.OrgID == active,
			})
		}
		json.NewEncoder(w).Encode(out)
	})

	// /api/admin/orgs — owner-only CRUD for org registry.
	// GET: full list (with tokens). POST: upsert {org_id, url, token, label}.
	// DELETE: {org_id}. PATCH: {org_id, active:true} to set active.
	mux.HandleFunc("/api/admin/orgs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, PATCH, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Cookie")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// GET 은 public — 이 호스트가 연결 가능한 조직 목록은 로그인 드롭다운
		// 등에서 비로그인 상태에도 필요. POST/DELETE/PATCH 만 owner 제한.
		if r.Method != http.MethodGet {
			sess, err := auth.SessionFromRequest(r, s.authProv)
			if err != nil || roles.Normalize(roles.Role(sess.Role)) != roles.Owner {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "소유자 권한 필요"})
				return
			}
		}

		switch r.Method {
		case http.MethodGet:
			// owner 면 전체 조회 (token 포함), 아니면 token 은 마스킹.
			isOwner := false
			if sess, err := auth.SessionFromRequest(r, s.authProv); err == nil && sess != nil {
				if roles.Normalize(roles.Role(sess.Role)) == roles.Owner {
					isOwner = true
				}
			}
			rawOrgs := s.orgs.List()
			orgs := make([]map[string]any, 0, len(rawOrgs))
			for _, o := range rawOrgs {
				entry := map[string]any{
					"org_id": o.OrgID,
					"url":    o.URL,
					"label":  o.Label,
				}
				if isOwner {
					entry["token"] = o.Token
				}
				orgs = append(orgs, entry)
			}
			json.NewEncoder(w).Encode(map[string]any{
				"active": s.orgs.ActiveID(),
				"orgs":   orgs,
			})
		case http.MethodPost:
			var body orgstore.Entry
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			// 토큰 검증: 입력받은 URL+토큰 으로 실제 /org/{id}/v1/users 를 찔러서 200 이 오는지 확인.
			testClient := orgserver.NewWithToken(body.URL, body.Token)
			if _, probeErr := testClient.ListUsers(body.OrgID); probeErr != nil {
				w.WriteHeader(http.StatusBadGateway)
				json.NewEncoder(w).Encode(map[string]string{"error": "조직서버 접속 실패: " + probeErr.Error()})
				return
			}
			if err := s.orgs.Upsert(body); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		case http.MethodDelete:
			var body struct {
				OrgID   string `json:"org_id"`
				Cascade bool   `json:"cascade"`
			}
			json.NewDecoder(r.Body).Decode(&body)

			// Cascade=true 면 조직 내 모든 사용자 + 워크스테이션 VM 을 먼저 제거.
			// Policy-server (Cloud Run) 자체 삭제는 별도 gcloud 커맨드 필요 (proxy 에 권한 없음).
			var purged []string
			var failed []map[string]string
			if body.Cascade {
				client := s.orgs.ClientFor(body.OrgID)
				users, err := client.ListUsers(body.OrgID)
				if err != nil {
					w.WriteHeader(http.StatusBadGateway)
					json.NewEncoder(w).Encode(map[string]string{"error": "사용자 목록 조회 실패: " + err.Error()})
					return
				}
				for _, u := range users {
					// 1) VM 삭제 (best-effort)
					if s.workstations != nil && u.Workstation != nil && u.Workstation.InstanceID != "" {
						ws := &userstore.Workstation{
							Provider:   u.Workstation.Provider,
							Platform:   u.Workstation.Platform,
							InstanceID: u.Workstation.InstanceID,
							Region:     u.Workstation.Region,
						}
						if err := s.workstations.Delete(r.Context(), u.Email, body.OrgID, ws); err != nil {
							failed = append(failed, map[string]string{"email": u.Email, "error": "vm: " + err.Error()})
						}
					}
					// 2) policy-server 에서 user 레코드 삭제
					if err := client.DeleteUser(body.OrgID, u.Email); err != nil {
						failed = append(failed, map[string]string{"email": u.Email, "error": "remote: " + err.Error()})
						continue
					}
					purged = append(purged, u.Email)
				}
			}
			if err := s.orgs.Remove(body.OrgID); err != nil {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"status":       "ok",
				"purged_users": purged,
				"failed":       failed,
				"cloud_run_note": "Cloud Run 서비스 (policy-server-" + body.OrgID + ") 는 별도 gcloud 명령으로 삭제 필요",
			})
		case http.MethodPatch:
			var body struct {
				OrgID  string `json:"org_id"`
				Active bool   `json:"active"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if body.Active {
				if err := s.orgs.SetActive(body.OrgID); err != nil {
					w.WriteHeader(http.StatusNotFound)
					json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
				}
			}
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		default:
			http.NotFound(w, r)
		}
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
			OrgID string `json:"org_id"` // multi-org: 로그인하려는 조직 선택
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
			roleVal, orgID, allowed, pendingMsg, err := resolveLoginAccess(body.Email, body.Email, loginType, body.OrgID, r)
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
			// TOFU IP 검증 (GCP 중앙) — resolveLoginAccess 뒤에 실행해서 user 가 GCP 에 sync 된 뒤 체크.
			if ok, msg := checkLoginIP(body.Email, orgID, r); !ok && msg != "" {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": msg})
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
			OrgID string `json:"org_id"`
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

		roleVal, orgID, allowed, pendingMsg, err := resolveLoginAccess(body.Email, body.Email, "email_otp", body.OrgID, r)
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

		// TOFU IP 검증 (GCP 중앙)
		if ok, msg := checkLoginIP(body.Email, orgID, r); !ok && msg != "" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": msg})
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

	// POST /api/auth/join-org — 한 줄 설치 후 사용자 가입 UX.
	// 입력: {email, url} — 소유자가 알려준 조직서버 URL + 사용자 이메일.
	// URL 에서 org_id 자동 파싱 → 공개 register → user_token 받아 orgs.json 저장.
	mux.HandleFunc("/api/auth/join-org", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var joinBody struct {
			Email string `json:"email"`
			URL   string `json:"url"`
		}
		json.NewDecoder(r.Body).Decode(&joinBody)
		joinBody.Email = strings.TrimSpace(strings.ToLower(joinBody.Email))
		joinBody.URL = strings.TrimRight(strings.TrimSpace(joinBody.URL), "/")
		if joinBody.Email == "" || joinBody.URL == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "조직서버 URL 과 이메일을 입력해주세요."})
			return
		}
		if !s.authProv.ValidateEmailDomain(joinBody.Email) {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{"error": "허용된 회사 이메일만 사용할 수 있습니다."})
			return
		}
		parsedOrgID, parseErr := orgstore.ExtractOrgIDFromURL(joinBody.URL)
		if parseErr != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": parseErr.Error()})
			return
		}
		payload, _ := json.Marshal(map[string]string{"email": joinBody.Email})
		req, _ := http.NewRequest(http.MethodPost, joinBody.URL+"/org/"+parsedOrgID+"/v1/public/register-request", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		httpClient := &http.Client{Timeout: 15 * time.Second}
		resp, err := httpClient.Do(req)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]string{"error": "조직서버 접속 실패: " + err.Error()})
			return
		}
		defer resp.Body.Close()
		var respBody struct {
			Status    string `json:"status"`
			Message   string `json:"message"`
			UserToken string `json:"user_token"`
			Error     string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&respBody)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			w.WriteHeader(resp.StatusCode)
			json.NewEncoder(w).Encode(map[string]string{"error": respBody.Error})
			return
		}
		// 이미 존재하는 org 면 기존 token (admin token 일 수 있음) 유지 — overwrite 하지 않음.
		// 신규 entry 만 user_token 으로 저장. 이 분리가 admin/user 권한을 분리.
		if _, exists := s.orgs.Get(parsedOrgID); !exists {
			if err := s.orgs.Add(orgstore.Entry{
				OrgID: parsedOrgID,
				URL:   joinBody.URL,
				Token: respBody.UserToken,
				Label: parsedOrgID,
			}); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": "로컬 저장 실패: " + err.Error()})
				return
			}
		}
		json.NewEncoder(w).Encode(map[string]string{
			"status":  respBody.Status,
			"message": respBody.Message,
			"org_id":  parsedOrgID,
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

		// Capture registration IP — only this IP can login as this user later.
		regIP := r.Header.Get("X-Forwarded-For")
		if regIP == "" {
			regIP = r.Header.Get("X-Real-IP")
		}
		if regIP == "" {
			regIP = r.RemoteAddr
		}
		if idx := strings.Index(regIP, ","); idx > 0 {
			regIP = strings.TrimSpace(regIP[:idx])
		}
		if idx := strings.LastIndex(regIP, ":"); idx > 0 {
			regIP = regIP[:idx]
		}
		u, err := s.users.RegisterWithIP(body.Email, body.Password, orgID, role, status, regIP)
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
		if err := s.orgs.ClientFor(orgID).RegisterUserWithState(orgID, body.Email, body.Password, role, string(status), machineID, machineName); err != nil {
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
			if remoteUsers, err := s.orgs.ClientFor(orgID).ListUsers(orgID); err == nil {
				// Index local by email for in-place update.
				localByEmail := make(map[string]*userstore.User)
				for _, u := range allUsers {
					localByEmail[strings.ToLower(u.Email)] = u
				}
				for _, ru := range remoteUsers {
					status := userstore.StatusPending
					if ru.Status == "approved" {
						status = userstore.StatusApproved
					}
					// policy-server 는 user 에 대해 `machine_id` 필드로 TOFU binding
					// 을 저장한다 (owner 는 `registered_ip` 사용 — 레거시 호환).
					// 로컬 UI 컬럼 (바인딩 PC) 은 둘 다 보여야 하므로 non-empty 쪽 선택.
					effectiveIP := ru.RegisteredIP
					if effectiveIP == "" {
						effectiveIP = ru.MachineID
					}
					if existing, ok := localByEmail[strings.ToLower(ru.Email)]; ok {
						// GCP 가 진실의 원천 — role/status/IP 등 최신 값으로 overlay.
						existing.Role = ru.Role
						existing.Status = status
						if effectiveIP != "" {
							existing.RegisteredIP = effectiveIP
						}
						continue
					}
					// Remote user not in local store — add.
					allUsers = append(allUsers, &userstore.User{
						Email:        ru.Email,
						Role:         ru.Role,
						OrgID:        orgID,
						Status:       status,
						RegisteredIP: effectiveIP,
						CreatedAt:    time.Now(),
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
				RegisteredIP      string `json:"registered_ip,omitempty"`
				WorkstationStatus string `json:"workstation_status,omitempty"`
				InstanceID        string `json:"instance_id,omitempty"`
			}
			out := make([]userView, 0, len(list))
			for _, u := range list {
				accessLevel := string(u.AccessLevel)
				if accessLevel == "" {
					accessLevel = "ask" // 기존 사용자 기본값
				}
				// 역할은 org policy-server 의 user 레코드에 저장된 값을 그대로 사용.
				// 로컬 env (BOAN_OWNER_EMAIL) 기반 매칭은 사용하지 않음 — 조직마다 owner 다를 수 있음.
				displayRole := roles.Normalize(roles.Role(u.Role))
				if displayRole != roles.Owner {
					displayRole = roles.User
				}
				out = append(out, userView{
					Email: u.Email,
					Role:  string(displayRole),
					OrgID:       u.OrgID,
					Status:      string(u.Status),
					AccessLevel: accessLevel,
					CreatedAt:    u.CreatedAt.Format("2006-01-02 15:04"),
					RegisteredIP: u.RegisteredIP,
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
				if err := s.orgs.ClientFor(defaultOrgID).RegisterUserWithState(defaultOrgID, body.Email, "", string(roles.User), "approved", "", ""); err != nil {
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
			if err := s.orgs.ClientFor(defaultOrgID).UpdateUser(defaultOrgID, body.Email, role, status, body.AccessLevel, workstation, machineID, machineName); err != nil {
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
			// 삭제 대상 조직 = 관리자 세션의 org. 세션 없으면 defaultOrgID.
			targetOrg := defaultOrgID
			if sess, err := auth.SessionFromRequest(r, s.authProv); err == nil && sess.OrgID != "" {
				targetOrg = sess.OrgID
			}

			// 1) GCP VM 삭제 시도 — workstation info 는 GCP org server 에서 조회 (local 에 없을 수 있음).
			if s.workstations != nil {
				var ws *userstore.Workstation
				// 우선 local 확인
				if local, _ := s.users.Workstation(body.Email); local != nil {
					ws = local
				} else if remoteUsers, err := s.orgs.ClientFor(targetOrg).ListUsers(targetOrg); err == nil {
					for _, ru := range remoteUsers {
						if strings.EqualFold(ru.Email, body.Email) && ru.Workstation != nil && ru.Workstation.InstanceID != "" {
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
				if ws != nil && ws.InstanceID != "" {
					if err := s.workstations.Delete(r.Context(), body.Email, targetOrg, ws); err != nil {
						log.Printf("workstation delete failed for %s (proceeding): %v", body.Email, err)
					} else {
						log.Printf("workstation deleted for %s (instance %s)", body.Email, ws.InstanceID)
					}
				}
			}
			// 2) local userstore 에서 제거 (있을 때만; 없어도 계속 진행)
			_ = s.users.Delete(body.Email)
			// 2a) bound_user 파일이 이 email 을 가리키면 clear — 안 그러면
			//     "이 PC 는 이미 다른 사용자 계정에 연결됨" 이라고 login 차단됨.
			clearBoundUserIfMatches(body.Email)
			// 3) org server 에서 제거 — 진실의 원천. 404 는 idempotent-OK
			// (로컬에만 있던 계정은 cloud 에 애초에 없으므로 not-found = 이미 삭제됨).
			if err := s.orgs.ClientFor(targetOrg).DeleteUser(targetOrg, body.Email); err != nil {
				if strings.Contains(err.Error(), "404") {
					log.Printf("[user-delete] org server 404 (already gone) for %s — treated as success", body.Email)
					json.NewEncoder(w).Encode(map[string]any{
						"status":  "ok",
						"warning": "사용자가 조직 서버에는 없었습니다 (로컬 전용 계정이었을 수 있음). VM + 로컬은 삭제됨.",
					})
					return
				}
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
		proposal, err := s.orgs.ClientFor(defaultOrgID).ProposeAmendment(defaultOrgID)
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
		proposal, err := s.orgs.ClientFor(defaultOrgID).ProposeG1Amendment(defaultOrgID)
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

	// attachOrgAuth — org-scoped 요청에 Bearer 토큰 자동 첨부.
	// orgstore 에서 해당 org 의 토큰을 꺼내 Authorization 헤더 세팅.
	attachOrgAuth := func(req *http.Request, orgID string) {
		if entry, ok := s.orgs.Resolve(orgID); ok && entry.Token != "" {
			req.Header.Set("Authorization", "Bearer "+entry.Token)
		}
	}

	// lookupLLMByRole — registry 에서 주어진 role 의 첫 LLM 조회.
	// 실제 model 이름은 registry 의 name 이 아니라 curl_template 안의 "model": "..."
	// 값이 정답 — ollama 등 로컬 백엔드는 그 값으로 매칭.
	// curl_template 에 {{CREDENTIAL:name}} 가 있으면 credential-filter 에서
	// 실제 토큰을 가져와 key 로 반환.
	modelRe := regexp.MustCompile(`"model"\s*:\s*"([^"]+)"`)
	credRe := regexp.MustCompile(`\{\{CREDENTIAL:([A-Za-z0-9_\-]+)\}\}`)
	lookupLLMByRole := func(role string) (url, model, key string, found bool) {
		if s.cfg.LLMRegistryURL == "" {
			return
		}
		regURL := strings.TrimRight(s.cfg.LLMRegistryURL, "/") + "/llm/list"
		resp, err := http.Get(regURL)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		var llms []struct {
			Name              string   `json:"name"`
			Endpoint          string   `json:"endpoint"`
			Roles             []string `json:"roles"`
			Healthy           bool     `json:"healthy"`
			CurlTemplate      string   `json:"curl_template"`
			ImageCurlTemplate string   `json:"image_curl_template"`
		}
		if json.NewDecoder(resp.Body).Decode(&llms) != nil {
			return
		}
		for _, l := range llms {
			if l.Endpoint == "" {
				continue
			}
			for _, rl := range l.Roles {
				if rl != role {
					continue
				}
				modelID := l.Name
				tmpl := l.CurlTemplate
				if tmpl == "" {
					tmpl = l.ImageCurlTemplate
				}
				if m := modelRe.FindStringSubmatch(tmpl); len(m) > 1 {
					modelID = m[1]
				}
				// {{CREDENTIAL:name}} → 실제 토큰 fetch.
				resolvedKey := ""
				if m := credRe.FindStringSubmatch(tmpl); len(m) > 1 && credBase != "" {
					credName := m[1]
					// resolveOrg defaults work; 여기선 default org 사용.
					credURL := strings.TrimRight(credBase, "/") + "/credential/" + s.cfg.OrgID + "/" + credName
					if cresp, err := http.Get(credURL); err == nil {
						defer cresp.Body.Close()
						if cresp.StatusCode < 300 {
							var body struct {
								Key string `json:"key"`
							}
							if err := json.NewDecoder(cresp.Body).Decode(&body); err == nil {
								resolvedKey = body.Key
							}
						}
					}
				}
				// endpoint 가 /v1/chat/completions 또는 /api/chat 로 끝나지 않으면 덧붙임.
				ep := l.Endpoint
				if !strings.Contains(ep, "/chat/completions") && !strings.HasSuffix(ep, "/chat") {
					ep = strings.TrimRight(ep, "/") + "/v1/chat/completions"
				}
				return ep, modelID, resolvedKey, true
			}
		}
		return
	}

	// ── Wiki Graph pass-through (Layer A primitive API) ──────────────
	// /api/wiki-graph/* → policy-server 의 /org/{id}/v1/wiki-graph/*
	mux.HandleFunc("/api/wiki-graph/", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		orgID := resolveOrg(r)
		orgURL := policyBase
		if entry, ok := s.orgs.Resolve(orgID); ok && entry.URL != "" {
			orgURL = entry.URL
		}
		suffix := strings.TrimPrefix(r.URL.Path, "/api/wiki-graph/")

		// skill/wiki_edit 은 LLM 호출이 필요한 composite endpoint — 별도 분기.
		if suffix == "skill/wiki_edit" && r.Method == http.MethodPost {
			var body wikiskills.Decision
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// LLM 찾기 — registry 의 g3 role 재사용 (또는 wiki_edit role 도 매칭).
			llmURL, llmModel, llmKey, found := lookupLLMByRole("wiki_edit")
			if !found {
				llmURL, llmModel, llmKey, found = lookupLLMByRole("g3")
			}
			if !found {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPreconditionFailed)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "LLM Registry 에 role=wiki_edit 또는 role=g3 로 바인딩된 LLM 없음",
				})
				return
			}
			// 로컬 token 확보.
			var orgToken string
			if entry, ok := s.orgs.Resolve(orgID); ok {
				orgToken = entry.Token
			}
			gc := wikiskills.NewGraphClient(orgURL, orgID, orgToken)
			res, err := wikiskills.RunWikiEdit(r.Context(), gc, wikiskills.LLMConfig{URL: llmURL, Model: llmModel, Key: llmKey}, body)
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				out := map[string]any{"error": err.Error()}
				if res != nil {
					out["partial_result"] = res
				}
				json.NewEncoder(w).Encode(out)
				return
			}
			json.NewEncoder(w).Encode(res)
			return
		}

		// skill/agentic_iterate — LLM 이 wiki 전체 + (옵션)dialog 를 읽고 편집 1회.
		if suffix == "skill/agentic_iterate" && r.Method == http.MethodPost {
			var body struct {
				DialogID string `json:"dialog_id,omitempty"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			llmURL, llmModel, llmKey, found := lookupLLMByRole("agentic_iterate")
			if !found {
				llmURL, llmModel, llmKey, found = lookupLLMByRole("g3")
			}
			if !found {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPreconditionFailed)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "LLM Registry 에 role=agentic_iterate 또는 role=g3 로 바인딩된 LLM 없음",
				})
				return
			}
			var orgToken string
			if entry, ok := s.orgs.Resolve(orgID); ok {
				orgToken = entry.Token
			}
			gc := wikiskills.NewGraphClient(orgURL, orgID, orgToken)
			res, err := wikiskills.RunAgenticIterate(r.Context(), gc, wikiskills.LLMConfig{URL: llmURL, Model: llmModel, Key: llmKey}, body.DialogID)
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				out := map[string]any{"error": err.Error()}
				if res != nil {
					out["partial_result"] = res
				}
				json.NewEncoder(w).Encode(out)
				return
			}
			json.NewEncoder(w).Encode(res)
			return
		}

		// skill/chat_continue — agentic loop 한 턴.
		// input: {dialog_id}
		// 반환: action + 새 LLM 턴 + (옵션) wiki_update 결과.
		if suffix == "skill/chat_continue" && r.Method == http.MethodPost {
			var body struct {
				DialogID string `json:"dialog_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DialogID == "" {
				http.Error(w, "dialog_id required", http.StatusBadRequest)
				return
			}
			llmURL, llmModel, llmKey, found := lookupLLMByRole("agentic_iterate")
			if !found {
				llmURL, llmModel, llmKey, found = lookupLLMByRole("g3")
			}
			if !found {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPreconditionFailed)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "LLM Registry 에 role=agentic_iterate 또는 role=g3 로 바인딩된 LLM 없음",
				})
				return
			}
			var orgToken string
			if entry, ok := s.orgs.Resolve(orgID); ok {
				orgToken = entry.Token
			}
			gc := wikiskills.NewGraphClient(orgURL, orgID, orgToken)
			res, err := wikiskills.RunChatContinue(r.Context(), gc, wikiskills.LLMConfig{URL: llmURL, Model: llmModel, Key: llmKey}, body.DialogID)
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
				return
			}

			// ── Part B: UPDATE_WIKI 후 "큰 변화" 이면 자동 개정 제안 체크 ──
			// actions_planned >= 2 (2 개 이상 노드 변경) 을 임계치로 잡음.
			// 조건 맞으면 background goroutine 으로 policy-server 에 propose-amendment
			// + propose-g1-amendment 호출. 결과가 있으면 approvalsStore 에 pending
			// 으로 쌓이고, 응답에 pending_amendment_check 플래그로 UI 에 알림.
			pendingAmend := []string{}
			if res.Action == "UPDATE_WIKI" && res.WikiUpdate != nil && res.WikiUpdate.ActionsPlanned >= 2 {
				// 동기 호출 — 너무 오래 걸리면 chat_continue 응답 지연될 수 있으나
				// propose-amendment 는 LLM 1 회 호출이라 5-10 초. 응답에 결과를
				// 담아서 UI 가 바로 "Approvals 확인" 배지 보이게 함.
				orgClient := s.orgs.ClientFor(orgID)
				if prop, perr := orgClient.ProposeAmendment(orgID); perr == nil {
					if diff, _ := prop["diff"].(string); strings.TrimSpace(diff) != "" {
						reasoning, _ := prop["reasoning"].(string)
						id := fmt.Sprintf("apr-%s", randomMachineID()[:12])
						approvalsMu.Lock()
						approvalsStore = append(approvalsStore, map[string]any{
							"id":          id,
							"sessionId":   "constitution",
							"command":     "constitution-amendment:review",
							"args":        []string{"diff=" + diff, "reasoning=" + reasoning},
							"requester":   "g3-wiki-chat-auto",
							"org_id":      orgID,
							"requestedAt": time.Now().UTC().Format(time.RFC3339),
							"status":      "pending",
						})
						approvalsMu.Unlock()
						pendingAmend = append(pendingAmend, "constitution:"+id)
					}
				} else {
					log.Printf("[chat_continue auto-amendment] ProposeAmendment failed: %v", perr)
				}
				if prop, perr := orgClient.ProposeG1Amendment(orgID); perr == nil {
					if diff, _ := prop["diff"].(string); strings.TrimSpace(diff) != "" {
						reasoning, _ := prop["reasoning"].(string)
						id := fmt.Sprintf("apr-%s", randomMachineID()[:12])
						approvalsMu.Lock()
						approvalsStore = append(approvalsStore, map[string]any{
							"id":          id,
							"sessionId":   "g1-patterns",
							"command":     "g1-amendment:review",
							"args":        []string{"diff=" + diff, "reasoning=" + reasoning},
							"requester":   "g3-wiki-chat-auto",
							"org_id":      orgID,
							"requestedAt": time.Now().UTC().Format(time.RFC3339),
							"status":      "pending",
						})
						approvalsMu.Unlock()
						pendingAmend = append(pendingAmend, "g1:"+id)
					}
				} else {
					log.Printf("[chat_continue auto-amendment] ProposeG1Amendment failed: %v", perr)
				}
			}

			// 응답에 pending_amendment 필드 얹어서 UI 가 배지 표시할 수 있게.
			resEnvelope := map[string]any{
				"action":           res.Action,
				"message":          res.Message,
				"examples":         res.Examples,
				"wiki_update":      res.WikiUpdate,
				"label_fix_target": res.LabelFixTarget,
				"llm_raw":          res.LLMRaw,
				"errors":           res.Errors,
			}
			if len(pendingAmend) > 0 {
				resEnvelope["pending_amendment"] = pendingAmend
			}
			json.NewEncoder(w).Encode(resEnvelope)
			return
		}

		// skill/label_fix_apply — HITL 사용자가 REQUEST_LABEL_FIX 제안을 Accept
		// 했을 때 실제로 decision 의 label 을 바꾼다. Reject 면 UI 측에서 아무것도
		// 호출 안 함. body: {decision_id, new_label, reason}
		if suffix == "skill/label_fix_apply" && r.Method == http.MethodPost {
			var body struct {
				DecisionID string `json:"decision_id"`
				NewLabel   string `json:"new_label"`
				Reason     string `json:"reason"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.DecisionID == "" || body.NewLabel == "" {
				http.Error(w, "decision_id + new_label required", http.StatusBadRequest)
				return
			}
			if body.NewLabel != "approve" && body.NewLabel != "deny" {
				http.Error(w, "new_label must be approve or deny", http.StatusBadRequest)
				return
			}
			var orgToken string
			if entry, ok := s.orgs.Resolve(orgID); ok {
				orgToken = entry.Token
			}
			gc := wikiskills.NewGraphClient(orgURL, orgID, orgToken)
			updated, err := gc.UpdateDecisionLabel(r.Context(), body.DecisionID, body.NewLabel, body.Reason)
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"status": "ok", "decision": updated})
			return
		}

		// skill/find_ambiguous — LLM 이 애매한 경계선 케이스 찾아서 질문 생성.
		if suffix == "skill/find_ambiguous" && r.Method == http.MethodPost {
			llmURL, llmModel, llmKey, found := lookupLLMByRole("find_ambiguous")
			if !found {
				llmURL, llmModel, llmKey, found = lookupLLMByRole("g3")
			}
			if !found {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPreconditionFailed)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "LLM Registry 에 role=find_ambiguous 또는 role=g3 로 바인딩된 LLM 없음",
				})
				return
			}
			var orgToken string
			if entry, ok := s.orgs.Resolve(orgID); ok {
				orgToken = entry.Token
			}
			gc := wikiskills.NewGraphClient(orgURL, orgID, orgToken)
			res, err := wikiskills.RunFindAmbiguous(r.Context(), gc, wikiskills.LLMConfig{URL: llmURL, Model: llmModel, Key: llmKey}, 20)
			w.Header().Set("Content-Type", "application/json")
			if err != nil {
				w.WriteHeader(http.StatusBadGateway)
				out := map[string]any{"error": err.Error()}
				if res != nil {
					out["partial_result"] = res
				}
				json.NewEncoder(w).Encode(out)
				return
			}
			json.NewEncoder(w).Encode(res)
			return
		}

		// 일반 primitive pass-through.
		target := orgURL + "/org/" + orgID + "/v1/wiki-graph/" + suffix
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		req, _ := http.NewRequestWithContext(r.Context(), r.Method, target, r.Body)
		req.Header.Set("Content-Type", "application/json")
		attachOrgAuth(req, orgID)
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
	})

	mux.HandleFunc("/api/policy/", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		orgID := resolveOrg(r)
		// Org 별 URL 로 전환 — policyBase env 대신 orgstore 에 저장된 URL 사용.
		orgURL := policyBase
		if entry, ok := s.orgs.Resolve(orgID); ok && entry.URL != "" {
			orgURL = entry.URL
		}
		rest := strings.TrimPrefix(r.URL.Path, "/api/policy")
		switch {
		case rest == "/v1/policy" && r.Method == http.MethodGet:
			req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet,
				orgURL+"/org/"+orgID+"/policy.json", nil)
			attachOrgAuth(req, orgID)
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
				orgURL+"/org/"+orgID+"/policy", bytes.NewReader(raw))
			req.Header.Set("Content-Type", "application/json")
			attachOrgAuth(req, orgID)
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
			// proxy helper 는 Authorization 헤더를 안 붙이므로 수동 요청.
			req, _ := http.NewRequestWithContext(r.Context(), http.MethodPost,
				orgURL+"/org/"+orgID+"/policy/rollback/1", r.Body)
			attachOrgAuth(req, orgID)
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
										s.orgs.ClientFor(orgID).UpdatePolicy(orgID, map[string]any{
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
			go s.orgs.ClientFor(orgID).AppendTrainingLog(orgID, map[string]any{
				"text":           approvalText,
				"mode":           approvalMode,
				"flagged_reason": approvalReason,
				"decision":       decision,
				"reasoning":      "human decision by owner",
				"confidence":     1.0,
				"source":         "human",
				"decided_by":     approvalRequester,
			})
			// Wiki Graph Raw 결정 이력에도 동시 append (LLM 이 관찰하는 원시 데이터).
			wikiDecision := "approve"
			if status != "approved" {
				wikiDecision = "deny"
			}
			go func(dec, input, reason, labeler string) {
				var orgToken string
				if entry, ok := s.orgs.Resolve(orgID); ok {
					orgToken = entry.Token
				}
				orgURL := policyBase
				if entry, ok := s.orgs.Resolve(orgID); ok && entry.URL != "" {
					orgURL = entry.URL
				}
				gc := wikiskills.NewGraphClient(orgURL, orgID, orgToken)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := gc.AppendDecision(ctx, wikiskills.Decision{
					Input:    input,
					Decision: dec,
					Reason:   reason,
					Labeler:  labeler,
				}); err != nil {
					log.Printf("[wiki-graph] append decision failed: %v", err)
				}
			}(wikiDecision, approvalText, approvalReason, approvalRequester)
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
	// Kill Chain — endpoint detection automated response.
	s.registerKillChainEndpoints(mux)

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

