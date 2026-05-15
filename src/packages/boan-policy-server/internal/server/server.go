package server

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-policy-server/internal/devicejwt"
	"github.com/samsung-sds/boanclaw/boan-policy-server/internal/policy"
	"github.com/samsung-sds/boanclaw/boan-policy-server/internal/signing"
)

const deviceJWTAudience = "boan-org-cloud"

type Config struct {
	Listen            string
	DataDir           string
	KeyDir            string
	OrgToken          string
	GuardrailLLMURL   string
	GuardrailLLMModel string
	GuardrailLLMKey   string
	WikiLLMURL        string
	WikiLLMModel      string
	WikiLLMKey        string
	// DevicePubKeys — comma-separated base64 Ed25519 pubkeys. When non-empty,
	// all /org/{id}/v1/* (non-public) requests MUST present a valid device JWT
	// in X-Boan-Device-JWT header. Absent/invalid → 401. fail-closed.
	DevicePubKeys  string
	RevokedDevices string
	// SystemNetworkEndpoints — CSV of mandatory egress entries that admins
	// cannot delete. Each item: "host[:port[/methods]]". Default port 443,
	// default method POST. Defended via prepend on every read + strip on
	// every write so that they survive `updatePolicy` round-trips.
	//
	// Without this the cloud LLM proxy host could be deleted by an admin
	// and the device would lose chat capability with no way to restore it
	// (the UI itself talks through the same proxy).
	SystemNetworkEndpoints string
}

func LoadConfig() Config {
	return Config{
		Listen: env("BOAN_LISTEN", ":8080"),
		DataDir: env("BOAN_DATA_DIR", "/data/policies"),
		KeyDir:  env("BOAN_KEY_DIR", "/etc/boan-policy"),
		// OrgToken: 이 policy-server 인스턴스의 조직 토큰.
		// 모든 /org/ 요청은 Authorization: Bearer <token> 헤더를 가져야 함.
		// 비어있으면 middleware 가 모든 요청을 401 로 거부 (fail-closed).
		// 각 Cloud Run 인스턴스(= 조직 1개) 마다 고유 토큰을 deploy 시 주입.
		OrgToken:          env("BOAN_ORG_TOKEN", ""),
		GuardrailLLMURL:   env("BOAN_GUARDRAIL_LLM_URL", ""),
		GuardrailLLMModel: env("BOAN_GUARDRAIL_LLM_MODEL", ""),
		GuardrailLLMKey:   env("BOAN_GUARDRAIL_LLM_KEY", ""),
		WikiLLMURL:        env("BOAN_WIKI_LLM_URL", ""),
		WikiLLMModel:      env("BOAN_WIKI_LLM_MODEL", ""),
		WikiLLMKey:        env("BOAN_WIKI_LLM_KEY", ""),
		DevicePubKeys:     env("BOAN_DEVICE_PUBKEYS", ""),
		RevokedDevices:    env("BOAN_REVOKED_DEVICES", ""),
		SystemNetworkEndpoints: env("BOAN_SYSTEM_NETWORK_ENDPOINTS", ""),
	}
}

// parseSystemEndpoints decodes the CSV form of BOAN_SYSTEM_NETWORK_ENDPOINTS
// into a slice of NetworkEndpoint with System=true. Each item supports:
//
//	host
//	host:port
//	host:port/METHOD,METHOD
//
// Empty input → empty slice (system list is optional). Invalid items are
// logged and skipped — boot proceeds so the rest of the policy stays usable.
func parseSystemEndpoints(csv string) []policy.NetworkEndpoint {
	out := []policy.NetworkEndpoint{}
	for _, raw := range strings.Split(csv, ",") {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		host := item
		port := 443
		methods := []string{"POST"}
		if i := strings.Index(item, "/"); i >= 0 {
			host = item[:i]
			ms := strings.Split(item[i+1:], "|")
			methods = methods[:0]
			for _, m := range ms {
				m = strings.ToUpper(strings.TrimSpace(m))
				if m != "" {
					methods = append(methods, m)
				}
			}
			if len(methods) == 0 {
				methods = []string{"POST"}
			}
		}
		if i := strings.LastIndex(host, ":"); i > 0 {
			var p int
			if _, err := fmt.Sscanf(host[i+1:], "%d", &p); err == nil && p > 0 && p <= 65535 {
				port = p
				host = host[:i]
			}
		}
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		out = append(out, policy.NetworkEndpoint{Host: host, Ports: []int{port}, Methods: methods, System: true})
	}
	return out
}

type Server struct {
	cfg           Config
	store         *policy.Store
	signer        *signing.Signer
	guardrail     *GuardrailEvaluator
	wikiGuardrail *GuardrailEvaluator
	trainingLog   *HITLTrainingLog
	wikiStore     *WikiStore
	wikiGraph     *policy.WikiGraphStore
	// devicePubs — parsed Ed25519 pubkeys. Empty → device JWT not required (dev only).
	devicePubs     []ed25519.PublicKey
	revokedDevices map[string]struct{}
	// broker — fans policy updates out to SSE subscribers (devices + admin UI).
	// Replaces / supplements the 60s polling on boan-proxy network.Gate so that
	// admin "−" / "+" / edit actions propagate to every device in <100 ms.
	broker *Broker
	// systemEndpoints — parsed from BOAN_SYSTEM_NETWORK_ENDPOINTS. Always
	// prepended on read and stripped on write so admins can't delete them.
	systemEndpoints []policy.NetworkEndpoint
	// orgPolicy — single API for all org-policy mutations. Routes every
	// patch (network whitelist, guardrail patterns, constitution, org
	// settings…) through one save+publish path. New mutation handlers
	// should call orgPolicy.Update instead of touching store directly.
	orgPolicy *OrgPolicy
}

type checkinRequest struct {
	InstanceID      string `json:"instance_id"`
	OrgID           string `json:"org_id"`
	BoanClawVersion string `json:"boanclaw_version"`
	OS              string `json:"os"`
	Hostname        string `json:"hostname"`
	UserID          string `json:"user_id"`
	Timestamp       string `json:"timestamp"`
	Signature       string `json:"sig"`
}

type checkinResponse struct {
	Status        string         `json:"status"`
	PolicyVersion int            `json:"policy_version,omitempty"`
	Policy        *policy.Policy `json:"policy,omitempty"`
	PolicySig     string         `json:"policy_sig,omitempty"`
	TTLSeconds    int            `json:"ttl_seconds,omitempty"`
	Reason        string         `json:"reason,omitempty"`
	Message       string         `json:"message,omitempty"`
	MinVersion    string         `json:"min_version,omitempty"`
}

func New(cfg Config) *Server {
	store := policy.NewStore(cfg.DataDir)
	os.MkdirAll(cfg.KeyDir, 0700)
	signer, _ := signing.LoadOrCreate(cfg.KeyDir+"/ed25519.priv", cfg.KeyDir+"/ed25519.pub")
	trainingLogPath := ""
	if cfg.DataDir != "" {
		trainingLogPath = cfg.DataDir + "/hitl_training.jsonl"
	}
	pubs, err := devicejwt.ParseAllowedPubs(cfg.DevicePubKeys)
	if err != nil {
		// fail-closed: refuse to start with malformed pubkeys
		panic(fmt.Sprintf("BOAN_DEVICE_PUBKEYS parse: %v", err))
	}
	revoked := map[string]struct{}{}
	for _, d := range strings.Split(cfg.RevokedDevices, ",") {
		if d = strings.TrimSpace(d); d != "" {
			revoked[d] = struct{}{}
		}
	}
	s := &Server{
		cfg:             cfg,
		store:           store,
		signer:          signer,
		guardrail:       NewGuardrailEvaluator(cfg.GuardrailLLMURL, cfg.GuardrailLLMModel, cfg.GuardrailLLMKey),
		wikiGuardrail:   NewGuardrailEvaluator(cfg.WikiLLMURL, cfg.WikiLLMModel, cfg.WikiLLMKey),
		trainingLog:     NewHITLTrainingLog(trainingLogPath),
		wikiStore:       NewWikiStore(cfg.DataDir),
		wikiGraph:       policy.NewWikiGraphStore(cfg.DataDir),
		devicePubs:      pubs,
		revokedDevices:  revoked,
		broker:          NewBroker(),
		systemEndpoints: parseSystemEndpoints(cfg.SystemNetworkEndpoints),
	}
	s.orgPolicy = newOrgPolicy(s)
	return s
}

// withSystemEndpoints prepends the mandatory system endpoints to `user` and
// dedupes by host (system wins). Caller is the policy reader — DB always
// stores only user-managed entries.
func (s *Server) withSystemEndpoints(user []policy.NetworkEndpoint) []policy.NetworkEndpoint {
	if len(s.systemEndpoints) == 0 {
		return user
	}
	seen := map[string]struct{}{}
	out := make([]policy.NetworkEndpoint, 0, len(s.systemEndpoints)+len(user))
	for _, e := range s.systemEndpoints {
		key := strings.ToLower(e.Host)
		out = append(out, e)
		seen[key] = struct{}{}
	}
	for _, e := range user {
		if _, dup := seen[strings.ToLower(e.Host)]; dup {
			continue
		}
		out = append(out, e)
	}
	return out
}

// stripSystemEndpoints removes any host that matches a system entry from the
// incoming update so the DB never persists them. Defends against an admin
// manually reposting a system row (UI 가 lock 해도 API 직접 호출 시).
func (s *Server) stripSystemEndpoints(incoming []policy.NetworkEndpoint) []policy.NetworkEndpoint {
	if len(s.systemEndpoints) == 0 {
		return incoming
	}
	sys := map[string]struct{}{}
	for _, e := range s.systemEndpoints {
		sys[strings.ToLower(e.Host)] = struct{}{}
	}
	out := make([]policy.NetworkEndpoint, 0, len(incoming))
	for _, e := range incoming {
		if _, isSys := sys[strings.ToLower(e.Host)]; isSys {
			continue
		}
		e.System = false // user-managed entries always have System=false
		out = append(out, e)
	}
	return out
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"service": "boan-policy-server",
			"status":  "ok",
			"routes": []string{
				"/healthz",
				"/pubkey",
				"/org/{org_id}/policy.json",
				"/org/{org_id}/network-policy.json",
				"/org/{org_id}/v1/policy",
				"/org/{org_id}/v1/org-settings",
				"/org/{org_id}/v1/checkin",
				"/org/{org_id}/v1/guardrail/evaluate",
				"/org/{org_id}/v1/wiki/compile",
				"/org/{org_id}/v1/wiki",
				"/org/{org_id}/v1/wiki/pages",
				"/org/{org_id}/v1/wiki/page/{path}",
			},
		})
	})
	// /org/* 는 토큰 검증 미들웨어로 감싼다 (단 /public/* 은 예외).
	mux.HandleFunc("/org/", func(w http.ResponseWriter, r *http.Request) {
		// /org/{id}/v1/public/* 는 인증 없이 허용 (가입 요청 등).
		// 조직 ID 만 알면 누구나 사용 요청 접수 가능. 스팸 방지는 이메일 도메인 필터 + rate limit 로.
		if strings.Contains(r.URL.Path, "/v1/public/") {
			s.handleOrg(w, r)
			return
		}
		s.requireOrgToken(s.handleOrg)(w, r)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("/pubkey", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string][]byte{"pub": s.signer.Pub})
	})

	srv := &http.Server{Addr: s.cfg.Listen, Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background())
	}()
	return srv.ListenAndServe()
}

// requireOrgToken — /org/ 요청에 Bearer + (옵션) device JWT 인증 요구.
// 통과 조건:
//   0. BOAN_DEVICE_PUBKEYS 가 설정된 경우 — X-Boan-Device-JWT 헤더가 있어야 하고
//      trusted pubkey 로 서명돼 있어야 함. revoked 디바이스 거부. fail-closed.
//   1. Token == BOAN_ORG_TOKEN (deployment-level, 전체 접근)
//   2. Token == user.UserToken (해당 조직에 등록된 user, 본인 상태 조회 등 제한된 접근)
//
// device JWT 가 활성화되면 "등록된 디바이스만" 호출 가능 → 외부 스캐너의
// Cloud Run 요청 폭주를 container 진입 전에 차단 가능 (GFE 에서 차단 안 되고
// container 에선 차단하지만 최소한 bearer+JWT 둘 다 없으면 빠르게 401 반환).
func (s *Server) requireOrgToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.OrgToken == "" {
			http.Error(w, "server not configured: BOAN_ORG_TOKEN unset", http.StatusUnauthorized)
			return
		}
		// 0) device JWT 검증 (활성화된 경우만) — bearer 보다 먼저 확인해서
		//    JWT 없이 스캐너가 bearer 추측하는 것 자체를 막는다.
		if len(s.devicePubs) > 0 {
			jwt := strings.TrimSpace(r.Header.Get("X-Boan-Device-JWT"))
			if jwt == "" {
				http.Error(w, "device JWT required (X-Boan-Device-JWT)", http.StatusUnauthorized)
				return
			}
			claims, err := devicejwt.Verify(jwt, s.devicePubs, deviceJWTAudience, 60*time.Second)
			if err != nil {
				http.Error(w, "device JWT invalid: "+err.Error(), http.StatusUnauthorized)
				return
			}
			if sub, ok := claims["sub"].(string); ok {
				if _, blocked := s.revokedDevices[sub]; blocked {
					http.Error(w, "device revoked", http.StatusForbidden)
					return
				}
				r.Header.Set("X-Boan-Verified-Device", sub)
			}
		}
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		token := auth[len(prefix):]
		if token == s.cfg.OrgToken {
			next(w, r)
			return
		}
		// 2) 사용자 토큰 확인 — URL 에서 org_id 추출 후 매칭.
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/org/"), "/")
		if len(parts) >= 1 {
			orgID := parts[0]
			user, err := s.store.FindUserByToken(orgID, token)
			if err == nil && user != nil {
				next(w, r)
				return
			}
		}
		http.Error(w, "invalid org token", http.StatusUnauthorized)
	}
}

func (s *Server) handleOrg(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/org/"), "/")
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	orgID := parts[0]
	rest := strings.Join(parts[1:], "/")

	switch {
	case rest == "v1/checkin" && r.Method == http.MethodPost:
		s.checkin(w, r, orgID)
	case rest == "v1/users" && r.Method == http.MethodGet:
		s.listUsers(w, orgID)
	case rest == "v1/users" && r.Method == http.MethodPatch:
		s.updateUser(w, r, orgID)
	case rest == "v1/users" && r.Method == http.MethodDelete:
		s.deleteUser(w, r, orgID)
	case rest == "v1/users/register" && r.Method == http.MethodPost:
		s.registerUser(w, r, orgID)
	case rest == "v1/users/sso-sync" && r.Method == http.MethodPost:
		s.syncSSOUser(w, r, orgID)
	case rest == "v1/users/check-login-ip" && r.Method == http.MethodPost:
		s.checkLoginIP(w, r, orgID)
	case rest == "v1/public/register-request" && r.Method == http.MethodPost:
		s.publicRegisterRequest(w, r, orgID)

	// ── Wiki Graph: primitive tools (Layer A) ─────────────────────────
	// LLM 이 자유롭게 조합해서 그래프를 편집할 수 있는 원시 API.
	// 노드 역할/타입은 하드코드 안 함 — 순수 그래프.
	case rest == "v1/wiki-graph/nodes" && r.Method == http.MethodGet:
		s.wgListNodes(w, orgID)
	case rest == "v1/wiki-graph/nodes" && r.Method == http.MethodPost:
		s.wgCreateNode(w, r, orgID)
	case strings.HasPrefix(rest, "v1/wiki-graph/nodes/") && r.Method == http.MethodGet:
		s.wgGetNode(w, orgID, strings.TrimPrefix(rest, "v1/wiki-graph/nodes/"))
	case strings.HasPrefix(rest, "v1/wiki-graph/nodes/") && r.Method == http.MethodPatch:
		s.wgUpdateNode(w, r, orgID, strings.TrimPrefix(rest, "v1/wiki-graph/nodes/"))
	case strings.HasPrefix(rest, "v1/wiki-graph/nodes/") && r.Method == http.MethodDelete:
		s.wgDeleteNode(w, orgID, strings.TrimPrefix(rest, "v1/wiki-graph/nodes/"))
	case rest == "v1/wiki-graph/edges" && r.Method == http.MethodGet:
		s.wgListEdges(w, orgID)
	case rest == "v1/wiki-graph/edges" && r.Method == http.MethodPost:
		s.wgCreateEdge(w, r, orgID)
	case strings.HasPrefix(rest, "v1/wiki-graph/edges/") && r.Method == http.MethodPatch:
		s.wgUpdateEdge(w, r, orgID, strings.TrimPrefix(rest, "v1/wiki-graph/edges/"))
	case strings.HasPrefix(rest, "v1/wiki-graph/edges/") && r.Method == http.MethodDelete:
		s.wgDeleteEdge(w, orgID, strings.TrimPrefix(rest, "v1/wiki-graph/edges/"))
	case rest == "v1/wiki-graph/decisions" && r.Method == http.MethodGet:
		s.wgListDecisions(w, r, orgID)
	case rest == "v1/wiki-graph/decisions" && r.Method == http.MethodPost:
		s.wgAppendDecision(w, r, orgID)
	case strings.HasPrefix(rest, "v1/wiki-graph/decisions/") && r.Method == http.MethodPatch:
		s.wgUpdateDecision(w, r, orgID, strings.TrimPrefix(rest, "v1/wiki-graph/decisions/"))
	case rest == "v1/wiki-graph/dialogs" && r.Method == http.MethodGet:
		s.wgListDialogs(w, r, orgID)
	case rest == "v1/wiki-graph/dialogs" && r.Method == http.MethodPost:
		s.wgUpsertDialog(w, r, orgID)
	case strings.HasPrefix(rest, "v1/wiki-graph/dialogs/") && r.Method == http.MethodDelete:
		s.wgDeleteDialog(w, orgID, strings.TrimPrefix(rest, "v1/wiki-graph/dialogs/"))
	case rest == "v1/users/reset-ip" && r.Method == http.MethodPost:
		s.resetUserIP(w, r, orgID)
	case rest == "v1/policy" && r.Method == http.MethodGet:
		s.getPolicy(w, orgID)
	case rest == "v1/policy" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
		s.updatePolicy(w, r, orgID)
	case rest == "v1/org-policy" && r.Method == http.MethodPatch:
		// PolicyPatch JSON 직접. 새 클라이언트 (frontend / agent) 가 이 endpoint
		// 만 쓰면 산발적인 wire format 없이 일관된 부분 업데이트 가능.
		s.patchOrgPolicy(w, r, orgID)
	case rest == "v1/org-settings" && r.Method == http.MethodGet:
		s.getOrgSettings(w, orgID)
	case rest == "v1/org-settings" && (r.Method == http.MethodPut || r.Method == http.MethodPatch):
		s.updateOrgSettings(w, r, orgID)
	case rest == "v1/guardrail/evaluate" && r.Method == http.MethodPost:
		s.evaluateGuardrail(w, r, orgID)
	case rest == "v1/guardrail/wiki-evaluate" && r.Method == http.MethodPost:
		s.wikiEvaluateGuardrail(w, r, orgID)
	case rest == "v1/guardrail/training-log" && r.Method == http.MethodPost:
		s.appendTrainingLog(w, r, orgID)
	case rest == "v1/guardrail/propose-amendment" && r.Method == http.MethodPost:
		s.proposeAmendment(w, r, orgID)
	case rest == "v1/guardrail/propose-g1-amendment" && r.Method == http.MethodPost:
		s.proposeG1Amendment(w, r, orgID)
	case rest == "v1/guardrail/gi1/forbidden" && r.Method == http.MethodPost:
		s.gi1Upload(w, r, orgID)
	case strings.HasPrefix(rest, "v1/guardrail/gi1/forbidden/") && r.Method == http.MethodDelete:
		s.gi1Delete(w, r, orgID, strings.TrimPrefix(rest, "v1/guardrail/gi1/forbidden/"))
	case rest == "v1/guardrail/gi1/threshold" && r.Method == http.MethodPut:
		s.gi1Threshold(w, r, orgID)
	case rest == "v1/guardrail/gi2/descriptions" && r.Method == http.MethodPut:
		s.gi2SetDescriptions(w, r, orgID)
	case rest == "v1/guardrail/auto-judge" && r.Method == http.MethodPost:
		s.autoJudge(w, r, orgID)
	case rest == "v1/guardrail/training-log" && r.Method == http.MethodGet:
		s.getTrainingLog(w, orgID)
	case rest == "v1/wiki/compile" && r.Method == http.MethodPost:
		s.compileWiki(w, r, orgID)
	case rest == "v1/wiki" && r.Method == http.MethodGet:
		s.getWikiIndex(w, orgID)
	case strings.HasPrefix(rest, "v1/wiki/page/") && r.Method == http.MethodGet:
		pagePath := strings.TrimPrefix(rest, "v1/wiki/page/")
		s.getWikiPage(w, pagePath)
	case rest == "v1/wiki/pages" && r.Method == http.MethodGet:
		s.getWikiPages(w)
	case rest == "policy.json" && r.Method == http.MethodGet:
		s.getPolicy(w, orgID)
	case rest == "policy" && r.Method == http.MethodPost:
		s.updatePolicy(w, r, orgID)
	case rest == "policy/versions" && r.Method == http.MethodGet:
		s.listVersions(w, orgID)
	case strings.HasPrefix(rest, "policy/rollback/") && r.Method == http.MethodPost:
		verStr := strings.TrimPrefix(rest, "policy/rollback/")
		s.rollbackPolicy(w, r, orgID, verStr)
	case rest == "network-policy.json" && r.Method == http.MethodGet:
		s.getSignedNetworkPolicy(w, orgID)
	case rest == "network-policy.stream" && r.Method == http.MethodGet:
		s.streamNetworkPolicy(w, r, orgID)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) getPolicy(w http.ResponseWriter, orgID string) {
	// OrgPolicy.Get 가 시스템 endpoint 주입 + 서명까지 처리. 핸들러는 직렬화만.
	p, err := s.orgPolicy.Get(context.Background(), orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

// patchOrgPolicy — clean PolicyPatch JSON endpoint. 새 클라이언트가 빈 슬라이스 vs
// "필드 보내지 않음" 명확히 구분할 수 있도록 pointer-based 페이로드 직접 수용.
// 기존 PUT /policy 핸들러는 backward compat 위해 유지하지만 내부적으로 동일
// orgPolicy.Update 호출 → 모든 mutation 이 한 path.
func (s *Server) patchOrgPolicy(w http.ResponseWriter, r *http.Request, orgID string) {
	var patch PolicyPatch
	if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if patch.IsEmpty() {
		http.Error(w, ErrPatchEmpty.Error(), http.StatusBadRequest)
		return
	}
	updated, err := s.orgPolicy.Update(r.Context(), orgID, patch)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(updated)
}

// updatePolicy 는 admin UI 의 PUT /policy 요청을 받아 PolicyPatch 로 변환한 뒤
// OrgPolicy.Update 단일 진입점에 위임한다. 기존엔 여기서 직접 store.Save +
// publish 했는데, 같은 흐름이 다른 곳에도 산재해서 한 군데로 모음. 새 mutation
// 핸들러 (org-settings/dlp/rbac 등) 도 PolicyPatch 만 만들어서 같은 메서드 호출.
func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request, orgID string) {
	var incoming policy.Policy
	if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	patch := PolicyPatch{}
	// 빈 슬라이스 vs 보내지 않음 구분이 어렵기 때문에 legacy wire format 은
	// "비어있지 않으면 의도된 변경"으로 해석. 새 클라이언트는 명시적으로
	// /v1/org-policy 같은 patch endpoint 를 쓰면 됨 (PolicyPatch 직접 JSON).
	if len(incoming.Network) > 0 {
		net := incoming.Network
		patch.NetworkWhitelist = &net
	}
	if len(incoming.DLPRules) > 0 {
		dlp := incoming.DLPRules
		patch.DLPRules = &dlp
	}
	if len(incoming.RBAC.Roles) > 0 || incoming.RBAC.DefaultRole != "" || incoming.RBAC.EnforceStrict {
		rbac := incoming.RBAC
		patch.RBAC = &rbac
	}
	if incoming.VersionPolicy.MinVersion != "" || len(incoming.VersionPolicy.BlockedVersions) > 0 || incoming.VersionPolicy.UpdateChannel != "" {
		vp := incoming.VersionPolicy
		patch.VersionPolicy = &vp
	}
	if incoming.OrgSettings.OrgName != "" || len(incoming.OrgSettings.AllowedSSO) > 0 || len(incoming.OrgSettings.AdminEmails) > 0 || incoming.OrgSettings.SeatLimit != 0 || incoming.OrgSettings.GCPOrgID != "" || incoming.OrgSettings.WorkspaceURL != "" || incoming.OrgSettings.MountRules != nil {
		os := incoming.OrgSettings
		patch.OrgSettings = &os
	}
	if strings.TrimSpace(incoming.Guardrail.GT2Constitution) != "" {
		c := incoming.Guardrail.GT2Constitution
		patch.GT2Constitution = &c
	}
	if incoming.Guardrail.GT1Patterns != nil {
		g1 := incoming.Guardrail.GT1Patterns
		patch.GT1Patterns = &g1
	}
	if incoming.Guardrail.GT3WikiHint != "" {
		hint := incoming.Guardrail.GT3WikiHint
		patch.GT3WikiHint = &hint
	}

	updated, err := s.orgPolicy.Update(r.Context(), orgID, patch)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"version": updated.Version})
}

// publishPolicyUpdate fans the latest signed network policy out to every SSE
// subscriber for orgID. Failures are swallowed — a polling client will pick
// up the update on its next 60s tick.
func (s *Server) publishPolicyUpdate(orgID string) {
	if s.broker == nil {
		return
	}
	payload, err := s.signedNetworkPolicyJSON(orgID)
	if err != nil {
		return
	}
	s.broker.Publish(orgID, payload)
}

func (s *Server) listVersions(w http.ResponseWriter, orgID string) {
	versions := s.store.ListVersions(orgID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(versions)
}

func (s *Server) rollbackPolicy(w http.ResponseWriter, r *http.Request, orgID string, verStr string) {
	ver, err := strconv.Atoi(verStr)
	if err != nil {
		http.Error(w, "invalid version", http.StatusBadRequest)
		return
	}
	updated, err := s.orgPolicy.Rollback(r.Context(), orgID, ver)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"rolled_back_to": ver, "new_version": updated.Version})
}

func (s *Server) getSignedNetworkPolicy(w http.ResponseWriter, orgID string) {
	payload, err := s.signedNetworkPolicyJSON(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
}

// signedNetworkPolicyJSON builds the exact wire format that getSignedNetworkPolicy
// returns (`{"policy": {...}, "signature": "..."}`) so the SSE stream can push
// the same bytes that a polling client would have fetched. Keeps subscribers
// signature-verified end-to-end. System endpoints are prepended here so
// every consumer (admin UI + device gates) sees the full effective list.
func (s *Server) signedNetworkPolicyJSON(orgID string) ([]byte, error) {
	p, err := s.store.EnsureDefault(orgID)
	if err != nil {
		return nil, err
	}
	policyDoc := map[string]any{
		"endpoints":  s.withSystemEndpoints(p.Network),
		"updated_at": p.UpdatedAt,
	}
	policyJSON, err := json.Marshal(policyDoc)
	if err != nil {
		return nil, err
	}
	sig, err := s.signer.SignBytes(policyJSON)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"policy":    json.RawMessage(policyJSON),
		"signature": sig,
	})
}

// streamNetworkPolicy is the SSE endpoint that pushes signed network-policy
// updates the moment they are saved. Clients (boan-proxy network.Gate and
// admin UI) subscribe here and receive the same JSON shape that
// `network-policy.json` returns — initial snapshot first, then one event per
// update. A 25s heartbeat keeps the connection through Cloud Run's idle
// trimming. The 60s polling cycle stays in place as a fallback for clients
// that drop the stream.
func (s *Server) streamNetworkPolicy(w http.ResponseWriter, r *http.Request, orgID string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	initial, err := s.signedNetworkPolicyJSON(orgID)
	if err == nil {
		fmt.Fprintf(w, "event: policy\ndata: %s\n\n", initial)
		flusher.Flush()
	}

	ch, cancel := s.broker.Subscribe(orgID)
	defer cancel()

	heartbeat := time.NewTicker(25 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case payload, alive := <-ch:
			if !alive {
				return
			}
			fmt.Fprintf(w, "event: policy\ndata: %s\n\n", payload)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) getOrgSettings(w http.ResponseWriter, orgID string) {
	p, err := s.store.EnsureDefault(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"org_id":       p.OrgID,
		"display_name": p.OrgSettings.OrgName,
		"settings": map[string]any{
			"allowed_sso":    p.OrgSettings.AllowedSSO,
			"admin_emails":   p.OrgSettings.AdminEmails,
			"seat_limit":     p.OrgSettings.SeatLimit,
			"gcp_org_id":     p.OrgSettings.GCPOrgID,
			"workspace_url":  p.OrgSettings.WorkspaceURL,
			"mount_root":     p.OrgSettings.MountRoot,
			"mount_rules":    p.OrgSettings.MountRules,
			"version_policy": p.VersionPolicy,
		},
		"updated_at": p.UpdatedAt,
	})
}

func (s *Server) updateOrgSettings(w http.ResponseWriter, r *http.Request, orgID string) {
	// 옛 코드는 store.Save 만 하고 broker.Publish 누락 — SSE 구독자가 변경
	// 못 받음. OrgPolicy.Update 로 위임해서 모든 mutation 이 같은 path 거치게.
	existing, err := s.store.EnsureDefault(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var body struct {
		DisplayName *string                `json:"display_name"`
		Settings    map[string]interface{} `json:"settings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// patch.OrgSettings 만 만들고 OrgPolicy.Update 로 위임. remarshal 헬퍼는
	// org-settings 키들을 policy.OrgSettings 필드로 매핑해주는 기존 로직.
	scratch := *existing
	if body.DisplayName != nil {
		scratch.OrgSettings.OrgName = strings.TrimSpace(*body.DisplayName)
	}
	if body.Settings != nil {
		if err := applyOrgSettingsPatch(&scratch, body.Settings); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	patch := PolicyPatch{
		OrgSettings:   &scratch.OrgSettings,
		VersionPolicy: &scratch.VersionPolicy, // org-settings 가 version_policy 도 같이 받을 수 있음
	}
	if _, err := s.orgPolicy.Update(r.Context(), orgID, patch); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.getOrgSettings(w, orgID)
}

func (s *Server) checkin(w http.ResponseWriter, r *http.Request, orgID string) {
	var req checkinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	p, err := s.store.EnsureDefault(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p.Signature = ""
	sig, err := s.signer.Sign(p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := checkinResponse{
		Status:        "allowed",
		PolicyVersion: p.Version,
		Policy:        p,
		PolicySig:     sig,
		TTLSeconds:    3600,
	}

	if req.BoanClawVersion == "" {
		resp.Status = "blocked"
		resp.Reason = "missing_version"
		resp.Message = "boanclaw_version is required"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(resp)
		return
	}

	for _, blocked := range p.VersionPolicy.BlockedVersions {
		if blocked == req.BoanClawVersion {
			resp.Status = "blocked"
			resp.Reason = "version_blocked"
			resp.Message = fmt.Sprintf("BoanClaw %s is blocked by organization policy.", req.BoanClawVersion)
			resp.MinVersion = p.VersionPolicy.MinVersion
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(resp)
			return
		}
	}

	if isVersionLess(req.BoanClawVersion, p.VersionPolicy.MinVersion) {
		resp.Status = "update_required"
		resp.Reason = "version_too_old"
		resp.Message = fmt.Sprintf("BoanClaw %s is below the minimum allowed version %s.", req.BoanClawVersion, p.VersionPolicy.MinVersion)
		resp.MinVersion = p.VersionPolicy.MinVersion
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(resp)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// publicRegisterRequest — 공개 가입 요청 엔드포인트 (인증 토큰 불필요).
// body: {email, name?}
// 조직 ID 만 아는 사용자가 이메일을 제출해서 pending user 로 등록될 수 있음.
// 조직 owner 가 UI 에서 승인하면 approved 로 전환.
// 스팸 방지는 이메일 중복 체크 + 이후 rate limit 추가 가능.
func (s *Server) publicRegisterRequest(w http.ResponseWriter, r *http.Request, orgID string) {
	var body struct {
		Email string `json:"email"`
		Name  string `json:"name,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	if body.Email == "" {
		http.Error(w, "email required", http.StatusBadRequest)
		return
	}
	name := body.Name
	if name == "" {
		name = body.Email
	}
	// 이미 등록된 user 면 중복 요청 에러 (status 상관없이).
	existing, _ := s.store.ListUsers(orgID)
	for _, u := range existing {
		if strings.EqualFold(u.Email, body.Email) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{
				"error":  "이미 등록된 이메일입니다.",
				"status": string(u.Status),
			})
			return
		}
	}
	user, err := s.store.UpsertSSOUser(orgID, body.Email, name, "user", "public-register", policy.UserStatusPending, "", "")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// 가입 즉시 user-specific token 발급. proxy 가 저장해서 이후 /org/* 호출에 Bearer 로 붙임.
	user.UserToken = policy.GenerateUserToken()
	if _, err := s.store.UpdateUser(orgID, user.Email, user.Role, user.Status, nil, user.MachineID, user.MachineName); err != nil {
		// 토큰 저장 실패해도 가입은 성공. 다음에 재발급 가능.
	} else {
		// UpdateUser 가 token 을 직접 건드리지 않으므로 별도 저장 필요.
		if err := s.store.SetUserToken(orgID, user.Email, user.UserToken); err != nil {
			http.Error(w, "token save failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":     "pending",
		"message":    "사용 요청이 접수되었습니다. 조직 소유자 승인 후 로그인할 수 있습니다.",
		"user_token": user.UserToken,
	})
}

// checkLoginIP — TOFU IP 바인딩 확인.
// body: {email, client_ip}
// resp: {allowed: bool, reason: "captured"|"match"|"ip_mismatch"|"user_not_found", registered_ip: string}
// 첫 로그인 시 clientIP 를 RegisteredIP 로 자동 저장 (TOFU).
// 이후 로그인부터는 저장된 IP 와 비교.
func (s *Server) checkLoginIP(w http.ResponseWriter, r *http.Request, orgID string) {
	var body struct {
		Email    string `json:"email"`
		ClientIP string `json:"client_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Email == "" || body.ClientIP == "" {
		http.Error(w, "email and client_ip are required", http.StatusBadRequest)
		return
	}
	allowed, reason, registeredIP, err := s.store.CheckOrCaptureLoginIP(orgID, body.Email, body.ClientIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"allowed":       allowed,
		"reason":        reason,
		"registered_ip": registeredIP,
	})
}

// resetUserIP — 관리자가 사용자 IP 재설정 (PC 교체 등).
func (s *Server) resetUserIP(w http.ResponseWriter, r *http.Request, orgID string) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.store.ResetUserIP(orgID, body.Email); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) listUsers(w http.ResponseWriter, orgID string) {
	users, err := s.store.ListUsers(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

func (s *Server) registerUser(w http.ResponseWriter, r *http.Request, orgID string) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
		Status   string `json:"status"`
		MachineID   string `json:"machine_id"`
		MachineName string `json:"machine_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Email == "" || body.Password == "" {
		http.Error(w, "email and password are required", http.StatusBadRequest)
		return
	}
	user, err := s.store.RegisterUserWithRole(orgID, body.Email, body.Password, body.Role, policy.UserStatus(body.Status), body.MachineID, body.MachineName)
	if err != nil {
		if err == policy.ErrUserExists {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func (s *Server) syncSSOUser(w http.ResponseWriter, r *http.Request, orgID string) {
	var body struct {
		Email    string `json:"email"`
		Name     string `json:"name"`
		Role     string `json:"role"`
		Provider string `json:"provider"`
		Status   string `json:"status"`
		MachineID   string `json:"machine_id"`
		MachineName string `json:"machine_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}
	if body.Provider == "" {
		body.Provider = "google"
	}
	user, err := s.store.UpsertSSOUser(orgID, body.Email, body.Name, body.Role, body.Provider, policy.UserStatus(body.Status), body.MachineID, body.MachineName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request, orgID string) {
	var body struct {
		Email       string              `json:"email"`
		Role        string              `json:"role"`
		Status      string              `json:"status"`
		Workstation *policy.Workstation `json:"workstation"`
		MachineID   string              `json:"machine_id"`
		MachineName string              `json:"machine_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.Email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}
	user, err := s.store.UpdateUser(orgID, body.Email, body.Role, policy.UserStatus(body.Status), body.Workstation, body.MachineID, body.MachineName)
	if err != nil {
		if err == policy.ErrUserNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request, orgID string) {
	email := strings.TrimSpace(r.URL.Query().Get("email"))
	if email == "" {
		var body struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			email = strings.TrimSpace(body.Email)
		}
	}
	if email == "" {
		http.Error(w, "email is required", http.StatusBadRequest)
		return
	}
	if err := s.store.DeleteUser(orgID, email); err != nil {
		if err == policy.ErrUserNotFound {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func applyOrgSettingsPatch(p *policy.Policy, settings map[string]interface{}) error {
	if raw, ok := settings["admin_emails"]; ok {
		var emails []string
		if err := remarshal(raw, &emails); err != nil {
			return fmt.Errorf("admin_emails: %w", err)
		}
		p.OrgSettings.AdminEmails = emails
	}
	if raw, ok := settings["allowed_sso"]; ok {
		var providers []policy.SSOProvider
		if err := remarshal(raw, &providers); err != nil {
			return fmt.Errorf("allowed_sso: %w", err)
		}
		p.OrgSettings.AllowedSSO = providers
	}
	if raw, ok := settings["seat_limit"]; ok {
		var seatLimit int
		if err := remarshal(raw, &seatLimit); err != nil {
			return fmt.Errorf("seat_limit: %w", err)
		}
		p.OrgSettings.SeatLimit = seatLimit
	}
	if raw, ok := settings["gcp_org_id"]; ok {
		var gcpOrgID string
		if err := remarshal(raw, &gcpOrgID); err != nil {
			return fmt.Errorf("gcp_org_id: %w", err)
		}
		p.OrgSettings.GCPOrgID = gcpOrgID
	}
	if raw, ok := settings["workspace_url"]; ok {
		var workspaceURL string
		if err := remarshal(raw, &workspaceURL); err != nil {
			return fmt.Errorf("workspace_url: %w", err)
		}
		p.OrgSettings.WorkspaceURL = workspaceURL
	}
	if raw, ok := settings["version_policy"]; ok {
		var versionPolicy policy.VersionPolicy
		if err := remarshal(raw, &versionPolicy); err != nil {
			return fmt.Errorf("version_policy: %w", err)
		}
		p.VersionPolicy = versionPolicy
	}
	return nil
}

func remarshal(in any, out any) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

func isVersionLess(version, minimum string) bool {
	if minimum == "" {
		return false
	}
	vParts := parseVersion(version)
	minParts := parseVersion(minimum)
	maxLen := len(vParts)
	if len(minParts) > maxLen {
		maxLen = len(minParts)
	}
	for i := 0; i < maxLen; i++ {
		v := 0
		if i < len(vParts) {
			v = vParts[i]
		}
		m := 0
		if i < len(minParts) {
			m = minParts[i]
		}
		if v < m {
			return true
		}
		if v > m {
			return false
		}
	}
	return false
}

func parseVersion(v string) []int {
	clean := strings.TrimSpace(strings.TrimPrefix(v, "v"))
	if clean == "" {
		return nil
	}
	parts := strings.Split(clean, ".")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

func (s *Server) autoJudge(w http.ResponseWriter, r *http.Request, orgID string) {
	w.Header().Set("Content-Type", "application/json")
	var req AutoJudgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p, err := s.store.EnsureDefault(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := s.guardrail.AutoJudge(r.Context(), p.Guardrail, s.trainingLog, orgID, req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.trainingLog.Append(HITLDecision{
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		OrgID:      orgID,
		Text:       req.Text,
		Mode:       req.Mode,
		Reason:     req.Reason,
		Decision:   resp.Decision,
		Reasoning:  resp.Reasoning,
		Confidence: resp.Confidence,
		Source:     "auto",
	})
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) proposeG1Amendment(w http.ResponseWriter, r *http.Request, orgID string) {
	w.Header().Set("Content-Type", "application/json")
	p, err := s.store.EnsureDefault(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	proposal, err := s.wikiGuardrail.ProposeG1Amendment(r.Context(), p.Guardrail, s.trainingLog)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	json.NewEncoder(w).Encode(proposal)
}

func (s *Server) getTrainingLog(w http.ResponseWriter, orgID string) {
	w.Header().Set("Content-Type", "application/json")
	entries := s.trainingLog.Recent(200)
	var filtered []HITLDecision
	for _, e := range entries {
		if e.OrgID == orgID || e.OrgID == "" {
			filtered = append(filtered, e)
		}
	}
	if filtered == nil {
		filtered = []HITLDecision{}
	}
	json.NewEncoder(w).Encode(filtered)
}

func (s *Server) compileWiki(w http.ResponseWriter, r *http.Request, orgID string) {
	w.Header().Set("Content-Type", "application/json")
	p, err := s.store.EnsureDefault(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Priority: request body > policy config > server config
	var body struct {
		LLMURL   string `json:"llm_url"`
		LLMModel string `json:"llm_model"`
	}
	json.NewDecoder(r.Body).Decode(&body)

	llmURL := s.cfg.WikiLLMURL
	llmModel := s.cfg.WikiLLMModel
	llmKey := s.cfg.WikiLLMKey
	if p.Guardrail.WikiLLMURL != "" {
		llmURL = p.Guardrail.WikiLLMURL
		llmModel = p.Guardrail.WikiLLMModel
	}
	// Request body overrides (from LLM Registry G3 binding)
	if body.LLMURL != "" {
		llmURL = body.LLMURL
	}
	if body.LLMModel != "" {
		llmModel = body.LLMModel
	}
	if err := s.wikiStore.Compile(r.Context(), llmURL, llmModel, llmKey, s.trainingLog, p.Guardrail); err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) getWikiIndex(w http.ResponseWriter, _ string) {
	w.Header().Set("Content-Type", "application/json")
	index, err := s.wikiStore.GetIndex()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pages := s.wikiStore.ListPages()
	json.NewEncoder(w).Encode(map[string]any{
		"index": index,
		"pages": pages,
	})
}

func (s *Server) getWikiPage(w http.ResponseWriter, pagePath string) {
	w.Header().Set("Content-Type", "application/json")
	content, err := s.wikiStore.GetPage(pagePath)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{
		"path":    pagePath,
		"content": content,
	})
}

func (s *Server) getWikiPages(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	pages := s.wikiStore.ListPages()
	// Return pages with their content
	type pageWithContent struct {
		Path      string `json:"path"`
		Title     string `json:"title"`
		UpdatedAt string `json:"updated_at"`
		Size      int64  `json:"size"`
		Content   string `json:"content"`
	}
	var result []pageWithContent
	for _, p := range pages {
		content, _ := s.wikiStore.GetPage(p.Path)
		result = append(result, pageWithContent{
			Path:      p.Path,
			Title:     p.Title,
			UpdatedAt: p.UpdatedAt,
			Size:      p.Size,
			Content:   content,
		})
	}
	if result == nil {
		result = []pageWithContent{}
	}
	json.NewEncoder(w).Encode(result)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
