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
	"image/jpeg"
	_ "image/png"
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
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/roles"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/userstore"
)

// cuQueuedCmd is a computer-use command waiting to be executed by the browser.
type cuQueuedCmd struct {
	id     string
	params map[string]any
	done   chan []byte
}

var (
	cuQueueMu     sync.Mutex
	cuPendingQueue []*cuQueuedCmd // waiting to be picked up by browser poll
	cuInFlight     []*cuQueuedCmd // picked up, waiting for result
)

var (
	approvalsMu    sync.Mutex
	approvalsStore []map[string]any
	pendingCredentialApprovals = map[string][]credentialApprovalCandidate{}
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

	type mountPolicyResponse struct {
		OrgSettings struct {
			MountRoot string `json:"mount_root"`
		} `json:"org_settings"`
	}

	mountRootForOrg := func(orgID string) string {
		defaultRoot := "/workspace/boanclaw"
		if strings.TrimSpace(s.cfg.PolicyURL) == "" {
			return defaultRoot
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.cfg.PolicyURL+"/org/"+orgID+"/policy.json", nil)
		if err != nil {
			return defaultRoot
		}
		resp, err := client.Do(req)
		if err != nil {
			return defaultRoot
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return defaultRoot
		}
		var policy mountPolicyResponse
		if err := json.NewDecoder(resp.Body).Decode(&policy); err != nil {
			return defaultRoot
		}
		if strings.TrimSpace(policy.OrgSettings.MountRoot) == "" {
			return defaultRoot
		}
		return filepath.Clean(policy.OrgSettings.MountRoot)
	}

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

	resolveLoginAccess := func(email, name, provider string) (roles.Role, string, bool, string, error) {
		email = strings.TrimSpace(strings.ToLower(email))
		orgID := defaultOrgID

		if ownerMatch(email) {
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
		role, gcpOrgID, allowed, pendingMsg, err := resolveLoginAccess(userInfo.Email, userInfo.Name, "google")
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
		role, orgID, allowed, pendingMsg, err := resolveLoginAccess(body.Email, body.Name, "google")
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

	runGCPSend := func(ctx context.Context, requester, orgID, text string) (string, error) {
		resp := evaluateInputGate(ctx, s.dlpEng, s.guardrail, orgID,
			InputGateRequest{Mode: "text", Text: text, SrcLevel: 3, DestLevel: 1, Flow: "openclaw-chat-to-remote-workstation"},
			func(reason string, req InputGateRequest) string {
				approvalID := createInputGateApproval(requester, orgID, reason, req)
				if s.cfg.PolicyURL != "" {
					go s.runAutoJudgeForApproval(approvalID, orgID, req.Text, req.Mode, reason)
				}
				return approvalID
			},
		)
		if resp.Action == "credential_required" && text != "" {
			gateResult := s.applyCredentialGate(ctx, orgID, text, func(keys []string, previews []string, fps []string) string {
				return createCredentialGateApproval(orgID, keys, previews, fps)
			})
			resp = InputGateResponse{Allowed: true, Action: "allow", NormalizedText: gateResult.Prompt, Reason: "credential substituted", ApprovalID: gateResult.ApprovalID}
			if gateResult.HITLRequired {
				resp.Reason = "credential detected; unknown values redacted, HITL created"
			}
		}
		if !resp.Allowed {
			if resp.Action == "hitl_required" && resp.ApprovalID != "" {
				return fmt.Sprintf("입력이 보류되었습니다. 관리자 승인 대기 중입니다. approval=%s", resp.ApprovalID), nil
			}
			return "", fmt.Errorf("가드레일에 통과되지 못하였습니다: 사유 - %s", firstNonEmptyString(resp.Reason, "input blocked"))
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
		prompt := extractPromptFromMessages(body["messages"])
		mode, payload := parseOperatorMode(prompt, "chat")
		log.Printf("[openclaw/v1] mode=%s payload=%.80q org=%s", mode, payload, orgID)

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
			if remoteURL, remoteErr := s.guac.EnsureSessionURL(r.Context(), ws); remoteErr == nil && remoteURL != "" {
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

		resp := evaluateInputGate(
			r.Context(),
			s.dlpEng,
			s.guardrail,
			sess.OrgID,
			body,
			func(reason string, req InputGateRequest) string {
				approvalID := createInputGateApproval(sess.Email, sess.OrgID, reason, req)
				// Auto-judge: check if org has auto_approve_mode on.
				if s.cfg.PolicyURL != "" {
					go s.runAutoJudgeForApproval(approvalID, sess.OrgID, req.Text, req.Mode, reason)
				}
				return approvalID
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
		if s.cfg.TestMode && ownerMatch(body.Email) {
			roleVal, orgID, allowed, pendingMsg, err := resolveLoginAccess(body.Email, body.Email, "test_owner")
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
			json.NewEncoder(w).Encode(map[string]any{
				"status":      "ok",
				"test_mode":   true,
				"bypass_otp":  true,
				"role":        string(roleVal),
				"role_label":  roles.Labels[roleVal],
				"org_id":      orgID,
				"hint":        "TEST 모드 소유자 계정은 OTP 없이 바로 로그인됩니다.",
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
		roleVal, orgID, allowed, pendingMsg, err := resolveLoginAccess(body.Email, body.Email, "email_otp")
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

		orgID := body.OrgID
		if orgID == "" {
			orgID = defaultOrgID
		}

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
			list := s.users.List()
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
			if ownerMatch(body.Email) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "고정 소유자는 변경할 수 없습니다."})
				return
			}
			if strings.TrimSpace(body.Role) == string(roles.Owner) {
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(map[string]string{"error": "소유자 권한은 고정 소유자에게만 부여할 수 있습니다."})
				return
			}
			if body.Action == "approve" {
				if err := s.users.Approve(body.Email); err != nil {
					w.WriteHeader(http.StatusNotFound)
					json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
					return
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
			if err := s.users.Delete(body.Email); err != nil {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
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

	mux.HandleFunc("/api/mount/config", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		orgID := resolveOrg(r)
		root := mountRootForOrg(orgID)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"org_id":      orgID,
			"mount_root":  root,
			"allowedDirs": []string{root},
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

	// ── 파일 매니저 API: S2(sandbox) ↔ S1(GCP) 파일 전송 ────────────────────

	// GET /api/files/list?path=&side=s2|s1 — 디렉토리 내용 조회
	mux.HandleFunc("/api/files/list", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) { return }
		w.Header().Set("Content-Type", "application/json")
		side := r.URL.Query().Get("side")
		reqPath := r.URL.Query().Get("path")
		orgID := resolveOrg(r)
		root := mountRootForOrg(orgID)

		var baseDir string
		switch side {
		case "s2":
			baseDir = root // sandbox mount directory
		case "s1":
			baseDir = "/workspace/gcp" // GCP workstation directory
		default:
			http.Error(w, `{"error":"side must be s2 or s1"}`, http.StatusBadRequest)
			return
		}

		target := filepath.Clean(filepath.Join(baseDir, reqPath))
		if !strings.HasPrefix(target, baseDir) {
			http.Error(w, `{"error":"path escapes base directory"}`, http.StatusForbidden)
			return
		}

		entries, err := os.ReadDir(target)
		if err != nil {
			// 디렉토리 없으면 빈 목록 반환
			if os.IsNotExist(err) {
				os.MkdirAll(target, 0755)
				json.NewEncoder(w).Encode(map[string]any{"path": reqPath, "side": side, "files": []any{}})
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		type fileEntry struct {
			Name  string `json:"name"`
			IsDir bool   `json:"is_dir"`
			Size  int64  `json:"size"`
		}
		files := make([]fileEntry, 0, len(entries))
		for _, e := range entries {
			info, _ := e.Info()
			size := int64(0)
			if info != nil {
				size = info.Size()
			}
			files = append(files, fileEntry{Name: e.Name(), IsDir: e.IsDir(), Size: size})
		}
		json.NewEncoder(w).Encode(map[string]any{"path": reqPath, "side": side, "files": files})
	})

	// POST /api/files/transfer — 파일 전송 (S2→S1: 가드레일 검사, S1→S2: 통과)
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
		orgID := resolveOrg(r)
		root := mountRootForOrg(orgID)
		s2Base := root
		s1Base := "/workspace/gcp"

		var srcFull, dstFull string
		switch body.SrcSide {
		case "s2":
			srcFull = filepath.Clean(filepath.Join(s2Base, body.SrcPath, body.FileName))
			dstFull = filepath.Clean(filepath.Join(s1Base, body.DstPath, body.FileName))
		case "s1":
			srcFull = filepath.Clean(filepath.Join(s1Base, body.SrcPath, body.FileName))
			dstFull = filepath.Clean(filepath.Join(s2Base, body.DstPath, body.FileName))
		default:
			http.Error(w, `{"error":"src_side must be s2 or s1"}`, http.StatusBadRequest)
			return
		}

		// 경로 탈출 방지
		if (body.SrcSide == "s2" && !strings.HasPrefix(srcFull, s2Base)) ||
			(body.SrcSide == "s1" && !strings.HasPrefix(srcFull, s1Base)) {
			http.Error(w, `{"error":"source path escapes base"}`, http.StatusForbidden)
			return
		}
		if (body.SrcSide == "s2" && !strings.HasPrefix(dstFull, s1Base)) ||
			(body.SrcSide == "s1" && !strings.HasPrefix(dstFull, s2Base)) {
			http.Error(w, `{"error":"dest path escapes base"}`, http.StatusForbidden)
			return
		}

		// 소스 파일 읽기
		info, err := os.Stat(srcFull)
		if err != nil {
			http.Error(w, `{"error":"source file not found"}`, http.StatusNotFound)
			return
		}
		if info.IsDir() {
			http.Error(w, `{"error":"directory transfer not allowed, files only"}`, http.StatusBadRequest)
			return
		}

		// S2 → S1: 가드레일 검사 (파일 내용)
		if body.SrcSide == "s2" {
			content, readErr := os.ReadFile(srcFull)
			if readErr != nil {
				http.Error(w, `{"error":"cannot read source file"}`, http.StatusInternalServerError)
				return
			}
			// 텍스트 파일만 가드레일 검사 (바이너리는 DLP)
			textContent := string(content)
			if len(textContent) > 0 {
				gateResp := evaluateInputGate(r.Context(), s.dlpEng, s.guardrail, defaultOrgID, InputGateRequest{
					Mode: "text", Text: textContent, SrcLevel: 2, DestLevel: 1,
					Flow: "file-transfer-s2-to-s1",
				}, nil)
				if !gateResp.Allowed {
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]any{
						"ok": false, "error": "guardrail blocked file transfer",
						"action": gateResp.Action, "reason": gateResp.Reason,
					})
					return
				}
			}
		}
		// S1 → S2: 무조건 통과

		// 파일 복사
		os.MkdirAll(filepath.Dir(dstFull), 0755)
		srcData, _ := os.ReadFile(srcFull)
		if err := os.WriteFile(dstFull, srcData, 0644); err != nil {
			http.Error(w, `{"error":"failed to write destination file: `+err.Error()+`"}`, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"ok": true, "src": srcFull, "dst": dstFull,
			"size": info.Size(), "guardrail": body.SrcSide == "s2",
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
					"allow_models":      []any{},
					"features":          map[string]bool{},
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
			if name := strings.TrimPrefix(rest, "/v1/passthrough/"); name != "" && r.Method == http.MethodDelete {
				if err := s.deleteCredentialPassthrough(orgID, name); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			id := strings.TrimPrefix(rest, "/v1/credentials/")
			if id != "" && r.Method == http.MethodDelete {
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
				gateResp := evaluateInputGate(r.Context(), s.dlpEng, s.guardrail, defaultOrgID, InputGateRequest{
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
	mux.HandleFunc("/api/computer-use/poll", func(w http.ResponseWriter, r *http.Request) {
		if cors(w, r) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
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
		gateResp := evaluateInputGate(r.Context(), s.dlpEng, s.guardrail, defaultOrgID, InputGateRequest{
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

	// POST /api/computer-use/agent — LLM이 직접 computer-use 명령 생성 및 실행
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
		orgID := resolveOrg(r)
		log.Printf("[computer-use/agent] received prompt=%q org=%s", agentReq.Prompt, orgID)

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

		// computer-use 큐에 액션을 넣고 프론트엔드 실행 결과를 대기하는 헬퍼
		// r.Context() 가 취소돼도 (프론트 연결 종료) 에이전트 루프는 계속 실행
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

		// open-computer-use sandbox_agent.py 패턴 동일 구현:
		// 1) vision_model(screenshot + prompt) → 화면 묘사 + next step (append_screenshot)
		// 2) action_model(thought + tools) → tool call JSON (action_model.call)
		// 3) 액션 실행 → stop 나올 때까지 반복 (최대 10 스텝)

		visionEntry, visionErr := s.loadSecurityLMM(r.Context())
		if visionErr != nil {
			log.Printf("[computer-use/agent] no security LMM: %v", visionErr)
			sendEvent(map[string]any{"type": "error", "text": "보안 LMM이 등록되지 않았습니다: " + visionErr.Error()})
			return
		}
		log.Printf("[computer-use/agent] vision LMM=%s", visionEntry.Name)

		const maxSteps = 10
		executed := 0
		lastScreenshotB64 := ""

		// ── 히스토리: 이전 스텝의 행동/결과를 누적하여 LLM에 전달 (Claude Computer Use 패턴)
		// 매 스텝마다 vision/action 이 이전 시도를 참조할 수 있도록 함
		type stepRecord struct {
			Step    int    `json:"step"`
			Thought string `json:"thought"`
			Actions string `json:"actions"`
			Result  string `json:"result"`
		}
		var stepHistory []stepRecord

		// visionPromptTemplate: %s=objective, %d=width, %d=height, %s=history
		visionPromptTemplate := "This image IS the screenshot of the current display (resolution: %dx%d pixels).\n" +
			"The objective is: %s\n" +
			"%s" +
			"Describe what is visible. For each UI element, estimate its center (x, y) in %dx%d pixels.\n" +
			"If the objective is to capture/show a screenshot, it is ALREADY COMPLETE.\n" +
			"End with exactly one line: OBJECTIVE: COMPLETE or OBJECTIVE: INCOMPLETE\n" +
			"If INCOMPLETE, describe the single next action and target coordinates."

		// actionSystemPromptFmt: %d=width, %d=height
		actionSystemPromptFmt := "You control a remote Windows workstation. Screen: %dx%d pixels.\n" +
			"Respond with ONLY a JSON array of actions. No explanation, no markdown.\n" +
			"Available actions:\n" +
			`{"action":"screenshot"}` + "\n" +
			`{"action":"type","text":"..."}` + "\n" +
			`{"action":"key","name":"..."}` + " – Return, Tab, Escape, BackSpace, ctrl+s, ctrl+c, ctrl+v, ctrl+z\n" +
			`{"action":"click","x":N,"y":N}` + "\n" +
			`{"action":"double_click","x":N,"y":N}` + "\n" +
			`{"action":"right_click","x":N,"y":N}` + "\n" +
			`{"action":"scroll","x":N,"y":N,"direction":"down","amount":3}` + "\n" +
			`{"action":"stop"}` + " – task complete\n" +
			`Example: [{"action":"click","x":100,"y":200}]`

		for step := 0; step < maxSteps; step++ {
			// Step A: 스크린샷 캡처
			sendEvent(map[string]any{"type": "status", "text": fmt.Sprintf("화면 캡처 중... (스텝 %d)", step+1)})
			ssResult, ssErr := queueAndWait(map[string]any{"action": "screenshot"})
			if ssErr != nil {
				log.Printf("[computer-use/agent] step=%d screenshot error: %v", step, ssErr)
				sendEvent(map[string]any{"type": "error", "text": "스크린샷 실패: " + ssErr.Error()})
				break
			}
			// boan-computer-use 서비스는 "image" 키로 반환, 구형 호환을 위해 "data"도 확인
			screenshotB64, _ := ssResult["image"].(string)
			if screenshotB64 == "" {
				screenshotB64, _ = ssResult["data"].(string)
			}
			if screenshotB64 == "" {
				log.Printf("[computer-use/agent] step=%d screenshot data empty, ssResult keys=%v", step, func() []string {
					keys := make([]string, 0, len(ssResult))
					for k := range ssResult { keys = append(keys, k) }
					return keys
				}())
				sendEvent(map[string]any{"type": "error", "text": "스크린샷 데이터 없음"})
				break
			}
			log.Printf("[computer-use/agent] step=%d screenshot ok, len=%d", step, len(screenshotB64))
			sendEvent(map[string]any{"type": "screenshot", "data": screenshotB64, "label": fmt.Sprintf("스텝 %d 화면", step+1)})
			lastScreenshotB64 = screenshotB64

			// 스크린샷 해상도 추출 (좌표 정확도 향상)
			scrW, scrH := getImageDimensions(screenshotB64)
			log.Printf("[computer-use/agent] step=%d screen resolution=%dx%d", step, scrW, scrH)

			// ── 히스토리 텍스트 구성: 이전 스텝 요약을 vision 프롬프트에 삽입
			historyText := ""
			if len(stepHistory) > 0 {
				historyText = "\n--- PREVIOUS ACTIONS (do NOT repeat failed actions) ---\n"
				for _, rec := range stepHistory {
					historyText += fmt.Sprintf("Step %d: thought=%q → actions=%s → result=%s\n",
						rec.Step, rec.Thought, rec.Actions, rec.Result)
				}
				historyText += "--- END PREVIOUS ACTIONS ---\n\n"
			}

			// Step B: vision LMM 호출 (sandbox_agent.append_screenshot 에 해당)
			sendEvent(map[string]any{"type": "status", "text": "Vision LMM이 화면을 분석 중..."})
			visionPrompt := fmt.Sprintf(visionPromptTemplate, scrW, scrH, agentReq.Prompt, historyText, scrW, scrH)
			thought, vErr := s.forwardVisionLLM(r.Context(), visionEntry, screenshotB64, visionPrompt)
			if vErr != nil {
				log.Printf("[computer-use/agent] vision llm error: %v", vErr)
				sendEvent(map[string]any{"type": "error", "text": "Vision LMM 오류: " + vErr.Error()})
				break
			}
			log.Printf("[computer-use/agent] step=%d thought len=%d thought=%q", step, len(thought), thought)
			sendEvent(map[string]any{"type": "thinking", "text": thought})

			// 완료 판단: vision 모델이 "OBJECTIVE: COMPLETE" 라고 하면 stop
			lowerThought := strings.ToLower(thought)
			isComplete := strings.Contains(lowerThought, "objective: complete") &&
				!strings.Contains(lowerThought, "objective: incomplete") &&
				!strings.Contains(lowerThought, "not complete")
			if isComplete {
				log.Printf("[computer-use/agent] vision says complete at step %d", step)
				compressedB64 := compressScreenshotForChat(screenshotB64)
				completedMsg := fmt.Sprintf("[gcp_exec] %s : 완료\n\n![](data:image/jpeg;base64,%s)", agentReq.Prompt, compressedB64)
				go injectOpenClawMessage(completedMsg)
				sendEvent(map[string]any{"type": "done", "actions_executed": executed})
				return
			}

			// Step C: action LMM 호출 (sandbox_agent.action_model.call 에 해당)
			// system/user 메시지를 분리하여 직접 전송 (forwardSelectedLLM의 고정 system 메시지 회피)
			sendEvent(map[string]any{"type": "status", "text": "Action LLM이 액션을 결정 중..."})
			actionSystemPrompt := fmt.Sprintf(actionSystemPromptFmt, scrW, scrH)
			actionUserPrompt := ""
			if len(stepHistory) > 0 {
				actionUserPrompt += "Previous steps:\n"
				for _, rec := range stepHistory {
					actionUserPrompt += fmt.Sprintf("- Step %d: %s → %s\n", rec.Step, rec.Actions, rec.Result)
				}
				actionUserPrompt += "\n"
			}
			actionUserPrompt += "Vision analysis:\n" + thought
			actionResp, aErr := s.forwardActionLLM(r.Context(), orgID, actionSystemPrompt, actionUserPrompt)
			if aErr != nil {
				log.Printf("[computer-use/agent] action llm error: %v", aErr)
				sendEvent(map[string]any{"type": "error", "text": "Action LLM 오류: " + aErr.Error()})
				break
			}
			actionText := ""
			if rawChoices, err := json.Marshal(actionResp["choices"]); err == nil {
				var choices []struct {
					Message struct{ Content string `json:"content"` } `json:"message"`
				}
				if json.Unmarshal(rawChoices, &choices) == nil && len(choices) > 0 {
					actionText = choices[0].Message.Content
				}
			}
			if actionText == "" {
				rawResp, _ := json.Marshal(actionResp)
				log.Printf("[computer-use/agent] step=%d action text EMPTY, raw response keys=%v full=%s", step, func() []string {
					keys := make([]string, 0)
					for k := range actionResp { keys = append(keys, k) }
					return keys
				}(), string(rawResp))
				sendEvent(map[string]any{"type": "error", "text": "Action LLM 빈 응답"})
				break
			}
			log.Printf("[computer-use/agent] step=%d action text=%s", step, actionText)

			// JSON 배열 파싱 (LLM이 잘못된 JSON을 줄 수 있으므로 정규화 시도)
			start := strings.Index(actionText, "[")
			end := strings.LastIndex(actionText, "]")
			if start < 0 || end <= start {
				log.Printf("[computer-use/agent] no action array in response, continuing")
				continue
			}
			jsonSlice := actionText[start : end+1]
			var actions []map[string]any
			if err := json.Unmarshal([]byte(jsonSlice), &actions); err != nil {
				// LLM이 숫자에 따옴표를 넣는 등의 오류 복구 시도: "285" → 285
				cleaned := strings.NewReplacer(`"action"`, `"action"`).Replace(jsonSlice)
				// 숫자값에 잘못 붙은 따옴표 제거: "x":"123" → "x":123
				numFixRe := regexp.MustCompile(`"(x|y|amount)"\s*:\s*"(\d+)"`)
				cleaned = numFixRe.ReplaceAllString(cleaned, `"$1":$2`)
				if err2 := json.Unmarshal([]byte(cleaned), &actions); err2 != nil {
					log.Printf("[computer-use/agent] action parse failed (original=%s, cleaned=%s): %v", jsonSlice, cleaned, err2)
					sendEvent(map[string]any{"type": "error", "text": "액션 파싱 실패: " + actionText})
					// 파싱 실패해도 다음 스텝으로 계속 진행 (break 대신 continue)
					continue
				}
				log.Printf("[computer-use/agent] step=%d action JSON fixed: %s → %s", step, jsonSlice, cleaned)
			}

			// Step D: 액션 실행
			stopped := false
			var stepActionDescs []string
			var stepResults []string
			for i, action := range actions {
				if action["action"] == "stop" {
					stopped = true
					break
				}
				actionJSON, _ := json.Marshal(action)
				log.Printf("[computer-use/agent] step=%d action[%d]: %s", step, i, actionJSON)
				sendEvent(map[string]any{"type": "action", "index": executed, "action": action})
				stepActionDescs = append(stepActionDescs, string(actionJSON))

				result, err := queueAndWait(action)
				if err != nil {
					log.Printf("[computer-use/agent] action error: %v", err)
					sendEvent(map[string]any{"type": "action_result", "index": executed, "error": err.Error()})
					stepResults = append(stepResults, "error:"+err.Error())
					if err.Error() == "cancelled" {
						return
					}
					stopped = true
					break
				}
				resultJSON, _ := json.Marshal(result)
				stepResults = append(stepResults, string(resultJSON))
				sendEvent(map[string]any{"type": "action_result", "index": executed, "result": result})
				executed++
				// 액션 실행 즉시 봇 채팅에 주입
				actionDesc := formatActionDesc(action)
				go injectOpenClawMessage(fmt.Sprintf("[gcp_exec] %s : [%d] %s", agentReq.Prompt, executed, actionDesc))
			}

			// ── 액션 실행 후 원격 데스크탑 반응 대기 (플립북 패턴: 결과 검증 전 대기)
			// Guacamole → RDP 전달 + 화면 렌더링에 시간이 필요
			if executed > 0 && !stopped {
				time.Sleep(800 * time.Millisecond)
			}

			// ── 히스토리 기록: 이번 스텝의 thought + actions + result 를 누적
			// thought 는 너무 길 수 있으므로 200자로 자름
			shortThought := thought
			if len(shortThought) > 200 {
				shortThought = shortThought[:200] + "..."
			}
			stepHistory = append(stepHistory, stepRecord{
				Step:    step + 1,
				Thought: shortThought,
				Actions: strings.Join(stepActionDescs, ","),
				Result:  strings.Join(stepResults, ","),
			})

			if stopped {
				break
			}
		}

		// 액션 없이 종료된 경우 — 에러가 아닌 경우에만 스크린샷 주입
		if executed == 0 && lastScreenshotB64 != "" {
			go injectOpenClawMessage(fmt.Sprintf("[gcp_exec] %s : 실행 실패 (액션 없음)", agentReq.Prompt))
		}
		sendEvent(map[string]any{"type": "done", "actions_executed": executed})
	})

	srv := &http.Server{
		Addr:              s.cfg.AdminListen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = srv.ListenAndServe()
	}()
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

// compressScreenshotForChat — PNG base64를 JPEG 소형으로 압축 (OpenClaw MARKDOWN_PARSE_LIMIT 40000자 이내)
// 최대 너비 400px로 축소 후 JPEG quality 40으로 재인코딩 → ~20-30KB base64
func compressScreenshotForChat(b64 string) string {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return b64
	}
	src, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return b64
	}

	// 최대 너비 400px 비율 축소
	bounds := src.Bounds()
	srcW, srcH := bounds.Dx(), bounds.Dy()
	maxW := 400
	dstW, dstH := srcW, srcH
	if srcW > maxW {
		dstW = maxW
		dstH = srcH * maxW / srcW
	}

	// nearest-neighbor 리사이즈
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
		return b64
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// formatActionDesc — computer-use 액션을 사람이 읽기 쉬운 문자열로 변환
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

// runAutoJudgeForApproval fetches the org policy to check auto_approve_mode,
// then calls policy-server auto-judge and immediately resolves the approval.
func (s *Server) runAutoJudgeForApproval(approvalID, orgID, text, mode, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Fetch policy to check auto_approve_mode flag.
	policyURL := strings.TrimRight(s.cfg.PolicyURL, "/") + "/org/" + orgID + "/policy.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, policyURL, nil)
	if err != nil {
		return
	}
	pResp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return
	}
	defer pResp.Body.Close()
	var pol struct {
		Guardrail struct {
			AutoApproveMode bool `json:"auto_approve_mode"`
		} `json:"guardrail"`
	}
	if err := json.NewDecoder(pResp.Body).Decode(&pol); err != nil {
		return
	}
	if !pol.Guardrail.AutoApproveMode {
		return // 수동 모드: 그냥 운영자 대기
	}

	// Call policy-server auto-judge endpoint.
	judgeURL := strings.TrimRight(s.cfg.PolicyURL, "/") + "/org/" + orgID + "/v1/guardrail/auto-judge"
	payload := map[string]string{"text": text, "mode": mode, "reason": reason}
	raw, _ := json.Marshal(payload)
	jReq, err := http.NewRequestWithContext(ctx, http.MethodPost, judgeURL, bytes.NewReader(raw))
	if err != nil {
		return
	}
	jReq.Header.Set("Content-Type", "application/json")
	jResp, err := (&http.Client{Timeout: 12 * time.Second}).Do(jReq)
	if err != nil {
		return
	}
	defer jResp.Body.Close()
	var judgeResult struct {
		Decision   string  `json:"decision"`
		Reasoning  string  `json:"reasoning"`
		Confidence float64 `json:"confidence"`
	}
	if err := json.NewDecoder(jResp.Body).Decode(&judgeResult); err != nil {
		return
	}

	newStatus := "rejected"
	if judgeResult.Decision == "approve" {
		newStatus = "approved"
	}

	// Update approval record in-memory.
	approvalsMu.Lock()
	for _, a := range approvalsStore {
		if a["id"] == approvalID {
			a["status"] = newStatus
			a["decidedBy"] = "auto-judge"
			a["decidedAt"] = time.Now().UTC().Format(time.RFC3339)
			a["auto_reasoning"] = judgeResult.Reasoning
			a["auto_confidence"] = judgeResult.Confidence
			break
		}
	}
	approvalsMu.Unlock()
	log.Printf("auto-judge approval=%s decision=%s confidence=%.2f reason=%q", approvalID, newStatus, judgeResult.Confidence, judgeResult.Reasoning)
}
