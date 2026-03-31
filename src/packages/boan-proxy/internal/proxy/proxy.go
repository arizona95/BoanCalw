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
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/dlp"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/network"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/orgserver"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/orgsettings"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/otp"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/promptguard"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/ratelimit"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/rbac"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/router"
	boantls "github.com/samsung-sds/boanclaw/boan-proxy/internal/tls"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/userstore"
)

type Server struct {
	cfg         *config.Config
	ca          *boantls.CA
	dlpEng      *dlp.Engine
	rbac        *rbac.Checker
	gate        *network.Gate
	creds       *credential.Manager
	router      *router.Router
	audit       *audit.Logger
	limiter     *ratelimit.Limiter
	authProv    *auth.Provider
	users       *userstore.Store
	orgSettings *orgsettings.Store
	orgServer   *orgserver.Client
	otpStore    *otp.Store
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
	} else {
		gate = network.NewGate(cfg.PolicyURL, cfg.OrgID)
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

	otpStore := otp.New(otp.SMTPConfig{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		User:     cfg.SMTPUser,
		Password: cfg.SMTPPassword,
		From:     cfg.SMTPFrom,
	})

	return &Server{
		cfg:         cfg,
		ca:          ca,
		dlpEng:      dlp.NewEngine(cfg.LocalLLMURL),
		rbac:        rbac.New(nil),
		gate:        gate,
		creds:       credential.NewManager(cfg.PolicyURL, cfg.OrgID),
		router:      rtr,
		limiter:     ratelimit.NewLimiter(10, 60),
		authProv:    authProv,
		users:       users,
		orgSettings: orgSettings,
		orgServer:   orgserver.New(cfg.PolicyURL),
		otpStore:    otpStore,
	}, nil
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
		if err := s.gate.Allow(r.Host, r.Method); err != nil {
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

func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if err := s.gate.Allow(r.Host, "CONNECT"); err != nil {
		http.Error(w, "blocked", http.StatusForbidden)
		s.logEvent(r, "block:network", dlp.SLevel1, err.Error(), nil)
		return
	}

	dest, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		dest.Close()
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		dest.Close()
		return
	}
	defer conn.Close()
	defer dest.Close()

	s.logEvent(r, "tunnel", dlp.SLevel1, "", nil)

	done := make(chan struct{}, 2)
	cp := func(a, b net.Conn) {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}
	go cp(dest, conn)
	go cp(conn, dest)
	<-done
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
