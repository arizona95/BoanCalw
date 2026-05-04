package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/audit"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/auth"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/config"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/credential"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/devicekey"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/dlp"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/guardrail"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/guac"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/network"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/orgserver"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/orgsettings"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/orgstore"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/otp"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/promptguard"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/ratelimit"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/rbac"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/router"
	boantls "github.com/samsung-sds/boanclaw/boan-proxy/internal/tls"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/killchain"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/threatleader"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/userstore"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/workstation"
)

type Server struct {
	cfg          *config.Config
	ca           *boantls.CA
	dlpEng       *dlp.Engine
	rbac         *rbac.Checker
	gate         *network.Gate
	creds        *credential.Manager
	router       *router.Router
	audit        *audit.Logger
	limiter      *ratelimit.Limiter
	authProv     *auth.Provider
	users        *userstore.Store
	orgSettings  *orgsettings.Store
	orgServer    *orgserver.Client
	orgs         *orgstore.Store
	otpStore     *otp.Store
	workstations workstation.Provisioner
	guac         *guac.Client
	guardrail    *guardrail.Client
	declinedFPs  *declinedFingerprintStore
	device       *devicekey.Identity
	killchain     *killchain.Store
	killchainRun  *killchain.Runner
	threatLeader  *threatleader.Store
	threatRefresh *threatleader.Refresher
}

func New(cfg *config.Config) (*Server, error) {
	ca, err := boantls.LoadOrCreateCA(cfg.TLSCACert, cfg.TLSCAKey)
	if err != nil {
		return nil, fmt.Errorf("CA: %w", err)
	}
	rtr, err := router.New(cfg.SecurityAgentURL, cfg.UsabilityAgentURL)
	if err != nil {
		return nil, err
	}

	var gate *network.Gate
	if cfg.NetworkPolicyPubKey != "" {
		pubKeyBytes, err := base64.StdEncoding.DecodeString(cfg.NetworkPolicyPubKey)
		if err != nil {
			return nil, fmt.Errorf("decode network policy pubkey: %w", err)
		}
		gate = network.NewGateWithKey(cfg.PolicyURL, cfg.OrgID, ed25519.PublicKey(pubKeyBytes))
		gate.SetToken(cfg.OrgToken)
	} else {
		gate = network.NewGateWithToken(cfg.PolicyURL, cfg.OrgID, cfg.OrgToken)
	}

	authProv := auth.New(auth.Config{
		ClientID:            cfg.OAuthClientID,
		ClientSecret:        cfg.OAuthClientSecret,
		RedirectURL:         cfg.OAuthRedirectURL,
		AppBaseURL:          cfg.AppBaseURL,
		AllowedEmailDomains: splitCSV(cfg.AllowedEmailDomains),
		JWTSecret:           cfg.JWTSecret,
		GCPOrgID:            cfg.GCPOrgID,
	})

	userDataDir := cfg.UserDataDir
	if userDataDir == "" {
		userDataDir = "/data/users"
	}
	users, err := userstore.New(userDataDir)
	if err != nil {
		log.Printf("userstore init warning: %v (using in-memory fallback)", err)
		users, _ = userstore.New(os.TempDir())
	}

	orgSettings, err := orgsettings.New(userDataDir)
	if err != nil {
		log.Printf("orgsettings init warning: %v", err)
		orgSettings, err = orgsettings.New(os.TempDir())
		if err != nil {
			return nil, fmt.Errorf("orgsettings: %w", err)
		}
	}

	// orgstore 레지스트리: 여러 조직 엔드포인트(URL+토큰) 를 저장.
	// 첫 기동 시 env (BOAN_ORG_ID/BOAN_POLICY_URL/BOAN_ORG_TOKEN) 로 seed.
	var seed *orgstore.Entry
	if cfg.OrgID != "" && cfg.PolicyURL != "" && cfg.OrgToken != "" {
		seed = &orgstore.Entry{
			OrgID: cfg.OrgID,
			URL:   cfg.PolicyURL,
			Token: cfg.OrgToken,
			Label: cfg.OrgID,
		}
	}
	orgs, err := orgstore.New(userDataDir+"/orgs.json", seed)
	if err != nil {
		log.Printf("orgstore init warning: %v", err)
		orgs, _ = orgstore.New(os.TempDir()+"/orgs.json", seed)
	}

	otpStore := otp.New(otp.SMTPConfig{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		User:     cfg.SMTPUser,
		Password: cfg.SMTPPassword,
		From:     cfg.SMTPFrom,
	})

	// Device identity (Ed25519 keypair) for signing JWTs to cloud services.
	// First boot generates + persists; subsequent boots reload.
	device, err := devicekey.Load(cfg.DeviceKeyPath)
	if err != nil {
		log.Printf("device key load warning: %v (JWT signing disabled)", err)
	} else {
		log.Printf("device identity loaded: id=%s pub_b64=%s...", device.DeviceID, device.PublicKeyBase64()[:32])
	}

	s := &Server{
		cfg:          cfg,
		ca:           ca,
		dlpEng:       dlp.NewEngine(cfg.LocalLLMURL, cfg.LocalLLMModel),
		rbac:         rbac.New(nil),
		gate:         gate,
		creds:        credential.NewManager(cfg.CredentialFilterURL, cfg.OrgID),
		router:       rtr,
		limiter:      ratelimit.NewLimiter(10, 60),
		authProv:     authProv,
		users:        users,
		orgSettings:  orgSettings,
		orgServer:    orgserver.NewWithToken(cfg.PolicyURL, cfg.OrgToken),
		orgs:         orgs,
		otpStore:     otpStore,
		workstations: func() workstation.Provisioner {
			prov := workstation.New(cfg)
			// orgSettings.golden_image_uri 가 있으면 provisioner 가 그 이미지로
			// 신규 사용자 VM 을 프로비저닝하도록 resolver 주입.
			if orgSettings != nil {
				workstation.AttachGoldenImageResolver(prov, func(orgID string) string {
					rec := orgSettings.GetOrCreate(orgID)
					if rec == nil {
						return ""
					}
					if v, ok := rec.Settings["golden_image_uri"].(string); ok {
						return v
					}
					return ""
				})
			}
			return prov
		}(),
		guac:         guac.New(cfg),
		guardrail:    guardrail.NewWithToken(cfg.PolicyURL, cfg.OrgToken),
		declinedFPs:  newDeclinedFingerprintStore(userDataDir),
		device:       device,
	}
	// Kill chain store + runner. 초기화 실패 시 fatal 하지 않음 — feature 자체가
	// optional. 실패 시 runner nil → UI 가 기능 비활성화.
	if kcStore, err := killchain.NewStore(userDataDir); err == nil {
		s.killchain = kcStore
		s.killchainRun = &killchain.Runner{Store: kcStore, Prov: s.workstations, Users: s.users}
	}
	// Threat Leader store + refresher (24h cron + 즉시 트리거).
	// userDataDir 가 host bind mount (uid 1000) 라 proxy uid 100 이 못 쓰는 경우가 있음.
	// /tmp/boan 은 컨테이너 ephemeral 이지만 proxy uid 가 항상 쓸 수 있고, 매일 fetch 라 재시작
	// 시 재구축 OK. 별도 영구 volume 은 phase v3 에 추가.
	tlDir := os.Getenv("BOAN_THREAT_LEADER_DIR")
	if tlDir == "" {
		tlDir = "/tmp/boan/threat-leader"
	}
	if tlStore, err := threatleader.NewStore(tlDir); err == nil {
		s.threatLeader = tlStore
		s.threatRefresh = threatleader.NewRefresher(tlStore)
		s.threatRefresh.Start(context.Background())
	} else {
		log.Printf("[threat-leader] init failed: %v (feature disabled)", err)
	}
	// 고아 GCP VM reaper — cleanup-user 가 한 번 더 빠뜨려도 비용이 영원히 누적되지
	// 않도록 하는 안전망. context.Background 사용 — 프로세스 lifetime 내내 동작.
	// BOAN_DISABLE_VM_JANITOR=1 로 끌 수 있다 — 같은 /data/users 를 공유하는
	// sandbox-embedded proxy 에서 standalone 컨테이너의 users.json (mode 0600)
	// 을 못 읽어 신규 VM 을 잘못 reap 하던 사고 (v10/v11) 회피용.
	if os.Getenv("BOAN_DISABLE_VM_JANITOR") != "1" {
		s.startVMJanitor(context.Background())
	} else {
		log.Printf("[vm-janitor] disabled (BOAN_DISABLE_VM_JANITOR=1)")
	}
	return s, nil
}

func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Server) DLPEngine() *dlp.Engine     { return s.dlpEng }
func (s *Server) Gate() *network.Gate        { return s.gate }
func (s *Server) Creds() *credential.Manager { return s.creds }
func (s *Server) Router() *router.Router     { return s.router }
func (s *Server) Audit() *audit.Logger       { return s.audit }
func (s *Server) CA() *boantls.CA            { return s.ca }

func (s *Server) Start(ctx context.Context) error {
	logger, err := audit.New(ctx, s.cfg.AuditEndpoint, s.cfg.OrgID)
	if err != nil {
		return err
	}
	s.audit = logger
	defer s.audit.Shutdown(context.Background())

	s.gate.StartRefresh(ctx, s.cfg.PolicyTTL)
	s.creds.StartRefresh(ctx, s.cfg.PolicyTTL)

	s.StartAdmin()
	log.Printf("boan-proxy listening on %s (admin: %s)", s.cfg.Listen, s.cfg.AdminListen)

	srv := &http.Server{
		Addr:    s.cfg.Listen,
		Handler: s.limiter.Middleware(http.HandlerFunc(s.ServeHTTP)),
		TLSConfig: &tls.Config{
			GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return s.ca.IssueForHost(hi.ServerName)
			},
		},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	return srv.ListenAndServe()
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		s.handleTunnel(w, r)
		return
	}
	s.handleHTTP(w, r)
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	isInternalAPI := r.URL.Host == "" && (r.URL.Path == "/api/llm-use" || r.URL.Path == "/healthz" || strings.HasPrefix(r.URL.Path, "/status"))
	if !isInternalAPI {
		if err := network.AllowRequest(s.gate, r); err != nil {
			http.Error(w, "blocked: "+err.Error(), http.StatusForbidden)
			s.logEvent(r, "block:network", dlp.SLevel1, err.Error(), nil)
			return
		}
	}

	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))

	decision, err := s.dlpEng.Inspect(r.Context(), bytes.NewReader(body))
	if err != nil || decision.Action == dlp.ActionBlock {
		reason := "inspect error"
		level := dlp.SLevel1
		if decision != nil {
			reason = decision.Reason
			level = decision.Level
		}
		http.Error(w, "blocked: sensitive data", http.StatusForbidden)
		s.logEvent(r, "block:dlp", level, reason, body)
		return
	}
	if decision.Action == dlp.ActionRedact {
		body = []byte(decision.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}

	ip := ratelimit.ExtractIP(r)

	tool := r.Header.Get("X-Boan-Tool")
	if tool != "" {
		if err := s.rbac.Check(r, tool); err != nil {
			s.limiter.RecordFailure(ip)
			http.Error(w, "forbidden: "+err.Error(), http.StatusForbidden)
			s.logEvent(r, "block:rbac", decision.Level, err.Error(), body)
			return
		}
	}
	s.limiter.Reset(ip)

	if r.Method == http.MethodPost && r.URL.Path == "/api/llm-use" {
		findings, err := promptguard.InspectBody(r)
		if err != nil {
			log.Printf("prompt guard: parse error: %v", err)
		} else if len(findings) > 0 {
			log.Printf("prompt guard: %d finding(s) from %s", len(findings), ip)
			for _, f := range findings {
				log.Printf("  pattern=%s match=%q", f.Pattern, f.Match)
			}
			w.Header().Set("X-Boan-Prompt-Findings", strconv.Itoa(len(findings)))
		}
	}

	s.creds.InjectHeader(r)
	s.logEvent(r, "allow", decision.Level, decision.Reason, body)

	proxy := s.router.Route(r, decision.Level)
	proxy.ServeHTTP(w, r)
}

// handleTunnel — HTTPS CONNECT tunnel. 기본 정책: 모든 raw CONNECT 차단 (HTTPS egress
// 는 inspect 가능한 path 로만). 단, network whitelist 에 host:port 가 등록되고 method 에
// "CONNECT" 가 명시된 경우만 raw forward 허용 — body inspection 은 양보하지만 host/port
// gate 와 audit log 는 유지.
//
// 사용 사례: github.com:443 같은 vendor API. credential vault 와 함께 git/MCP tool 이
// 동작할 수 있게 하는 안전한 tunnel path.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	bareHost, portStr, err := net.SplitHostPort(host)
	if err != nil {
		bareHost, portStr = host, "443"
	}
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}

	// fail-closed: gate 미초기화면 모든 CONNECT 거부.
	if s.gate == nil {
		reason := "raw CONNECT tunnel disabled: gate not initialized (fail-closed)"
		http.Error(w, reason, http.StatusForbidden)
		return
	}
	if err := s.gate.AllowWithPort(bareHost, http.MethodConnect, port); err != nil {
		reason := "raw CONNECT tunnel disabled: " + err.Error() +
			" (whitelist 에 host:port + methods=[CONNECT] 등록 필요)"
		http.Error(w, reason, http.StatusForbidden)
		s.logEvent(r, "block:connect", dlp.SLevel1, reason, nil)
		return
	}

	// Whitelist 통과 → raw byte tunnel.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "hijack failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	upstream, err := dialer.Dial("tcp", net.JoinHostPort(bareHost, strconv.Itoa(port)))
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		s.logEvent(r, "block:connect-dial", dlp.SLevel1, err.Error(), nil)
		return
	}
	defer upstream.Close()

	// 200 응답 후 raw stream
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	s.logEvent(r, "allow:connect", dlp.SLevel1, "tunneled (no body inspection)", nil)

	// bidirectional pipe
	go io.Copy(upstream, clientConn) //nolint:errcheck
	io.Copy(clientConn, upstream)    //nolint:errcheck
}

func (s *Server) logEvent(r *http.Request, action string, level dlp.SLevel, reason string, body []byte) {
	if s.audit == nil {
		return
	}
	hash := ""
	if len(body) > 0 {
		hash = audit.HashBody(body)
	}
	s.audit.Log(r.Context(), audit.Event{
		Action:   action,
		SLevel:   int(level),
		BodyHash: hash,
		Host:     r.Host,
		User:     r.Header.Get("X-Boan-Role"),
		Reason:   reason,
		Tool:     r.Header.Get("X-Boan-Tool"),
		Method:   r.Method,
	})
}
