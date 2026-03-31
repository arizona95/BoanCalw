package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/auth"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/roles"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/userstore"
)

var (
	approvalsMu    sync.Mutex
	approvalsStore []map[string]any
)

func (s *Server) StartAdmin() {
	mux := http.NewServeMux()
	client := &http.Client{Timeout: 5 * time.Second}

	defaultOrgID := s.cfg.OrgID
	ownerEmail := strings.ToLower(strings.TrimSpace(s.cfg.OwnerEmail))
	ownerMatch := func(email string) bool {
		return ownerEmail != "" && strings.EqualFold(strings.TrimSpace(email), ownerEmail)
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

	syncLocalUser := func(email, orgID, role string, status userstore.Status) {
		_, _ = s.users.Upsert(strings.TrimSpace(strings.ToLower(email)), orgID, role, status)
	}

	syncOrgUser := func(email, name, orgID, role, provider, status string) error {
		return s.orgServer.SyncUser(orgID, strings.TrimSpace(strings.ToLower(email)), name, role, provider, status)
	}

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
		googleConfigured := s.authProv.Enabled()
		ssoProviders := []map[string]any{
			{
				"id":           "google",
				"label":        "Google",
				"url":          "/api/auth/login",
				"configured":   googleConfigured,
				"setup_url":    "https://console.cloud.google.com/apis/credentials",
				"redirect_uri": callbackURL(r),
			},
		}
		json.NewEncoder(w).Encode(map[string]any{
			"sso_providers":         ssoProviders,
			"redirect_url":          callbackURL(r),
			"allowed_email_domains": splitCSV(s.cfg.AllowedEmailDomains),
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
				"error":   pendingMsg,
				"status":  "pending_approval",
				"org_id":  gcpOrgID,
				"email":   userInfo.Email,
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
			w.WriteHeader(http.StatusUnauthorized)
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

		sess := &auth.Session{
			Sub:   body.Email,
			Email: body.Email,
			Name:  body.Email,
			Role:  roleVal,
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
		json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"role":       string(roleVal),
			"role_label": roles.Labels[roleVal],
			"org_id":     orgID,
		})
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

		sess := &auth.Session{
			Sub:   body.Email,
			Email: body.Email,
			Name:  body.Email,
			Role:  roleVal,
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
		if err := s.orgServer.RegisterUserWithState(orgID, body.Email, body.Password, role, string(status)); err != nil {
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
				Email     string `json:"email"`
				Role      string `json:"role"`
				OrgID     string `json:"org_id"`
				Status    string `json:"status"`
				CreatedAt string `json:"created_at"`
			}
			out := make([]userView, 0, len(list))
			for _, u := range list {
				out = append(out, userView{
					Email:     u.Email,
					Role: func() string {
						if ownerMatch(u.Email) {
							return string(roles.Owner)
						}
						return string(roles.User)
					}(),
					OrgID:     u.OrgID,
					Status:    string(u.Status),
					CreatedAt: u.CreatedAt.Format("2006-01-02 15:04"),
				})
			}
			json.NewEncoder(w).Encode(out)
			return
		}

		if r.Method == http.MethodPatch {
			var body struct {
				Email  string `json:"email"`
				Role   string `json:"role"`
				Action string `json:"action"`
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
			if err := s.orgServer.UpdateUser(defaultOrgID, body.Email, role, status); err != nil {
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

	cors := func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return true
		}
		return false
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
		case rest == "/v1/llms" && r.Method == http.MethodPost:
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			raw, _ := json.Marshal(body)
			r.Body = io.NopCloser(bytes.NewReader(raw))
			proxy(w, r, registryBase+"/llm/register")
		default:
			if strings.Contains(rest, "/bind-security") {
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

		default:
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
		if len(parts) < 2 || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		id := parts[0]
		action := parts[1]
		approvalsMu.Lock()
		for i, a := range approvalsStore {
			if a["id"] == id {
				approvalsStore[i]["status"] = action
				approvalsStore[i]["decided_at"] = time.Now().UTC().Format(time.RFC3339)
				break
			}
		}
		approvalsMu.Unlock()
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusNoContent)
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
