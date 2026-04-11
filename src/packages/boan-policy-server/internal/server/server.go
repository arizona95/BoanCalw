package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-policy-server/internal/policy"
	"github.com/samsung-sds/boanclaw/boan-policy-server/internal/signing"
)

type Config struct {
	Listen            string
	DataDir           string
	KeyDir            string
	GuardrailLLMURL   string
	GuardrailLLMModel string
	GuardrailLLMKey   string
	WikiLLMURL        string
	WikiLLMModel      string
	WikiLLMKey        string
}

func LoadConfig() Config {
	return Config{
		Listen:            env("BOAN_LISTEN", ":8080"),
		DataDir:           env("BOAN_DATA_DIR", "/data/policies"),
		KeyDir:            env("BOAN_KEY_DIR", "/etc/boan-policy"),
		GuardrailLLMURL:   env("BOAN_GUARDRAIL_LLM_URL", ""),
		GuardrailLLMModel: env("BOAN_GUARDRAIL_LLM_MODEL", ""),
		GuardrailLLMKey:   env("BOAN_GUARDRAIL_LLM_KEY", ""),
		WikiLLMURL:        env("BOAN_WIKI_LLM_URL", ""),
		WikiLLMModel:      env("BOAN_WIKI_LLM_MODEL", ""),
		WikiLLMKey:        env("BOAN_WIKI_LLM_KEY", ""),
	}
}

type Server struct {
	cfg           Config
	store         *policy.Store
	signer        *signing.Signer
	guardrail     *GuardrailEvaluator
	wikiGuardrail *GuardrailEvaluator
	trainingLog   *HITLTrainingLog
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
	return &Server{
		cfg:           cfg,
		store:         store,
		signer:        signer,
		guardrail:     NewGuardrailEvaluator(cfg.GuardrailLLMURL, cfg.GuardrailLLMModel, cfg.GuardrailLLMKey),
		wikiGuardrail: NewGuardrailEvaluator(cfg.WikiLLMURL, cfg.WikiLLMModel, cfg.WikiLLMKey),
		trainingLog:   NewHITLTrainingLog(trainingLogPath),
	}
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
			},
		})
	})
	mux.HandleFunc("/org/", s.handleOrg)
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
	case rest == "v1/policy" && r.Method == http.MethodGet:
		s.getPolicy(w, orgID)
	case rest == "v1/policy" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
		s.updatePolicy(w, r, orgID)
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
	case rest == "v1/guardrail/auto-judge" && r.Method == http.MethodPost:
		s.autoJudge(w, r, orgID)
	case rest == "v1/guardrail/training-log" && r.Method == http.MethodGet:
		s.getTrainingLog(w, orgID)
	case rest == "policy.json" && r.Method == http.MethodGet:
		s.getPolicy(w, orgID)
	case rest == "policy" && r.Method == http.MethodPost:
		s.updatePolicy(w, r, orgID)
	case rest == "policy/versions" && r.Method == http.MethodGet:
		s.listVersions(w, orgID)
	case strings.HasPrefix(rest, "policy/rollback/") && r.Method == http.MethodPost:
		verStr := strings.TrimPrefix(rest, "policy/rollback/")
		s.rollbackPolicy(w, orgID, verStr)
	case rest == "network-policy.json" && r.Method == http.MethodGet:
		s.getSignedNetworkPolicy(w, orgID)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) getPolicy(w http.ResponseWriter, orgID string) {
	p, err := s.store.EnsureDefault(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	p.Signature = ""
	sig, _ := s.signer.Sign(p)
	p.Signature = sig
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request, orgID string) {
	existing, err := s.store.EnsureDefault(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var incoming policy.Policy
	if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	p := *existing
	if len(incoming.Network) > 0 {
		p.Network = incoming.Network
	}
	if len(incoming.DLPRules) > 0 {
		p.DLPRules = incoming.DLPRules
	}
	if len(incoming.RBAC.Roles) > 0 || incoming.RBAC.DefaultRole != "" || incoming.RBAC.EnforceStrict {
		p.RBAC = incoming.RBAC
	}
	if incoming.VersionPolicy.MinVersion != "" || len(incoming.VersionPolicy.BlockedVersions) > 0 || incoming.VersionPolicy.UpdateChannel != "" {
		p.VersionPolicy = incoming.VersionPolicy
	}
	if incoming.OrgSettings.OrgName != "" || len(incoming.OrgSettings.AllowedSSO) > 0 || len(incoming.OrgSettings.AdminEmails) > 0 || incoming.OrgSettings.SeatLimit != 0 || incoming.OrgSettings.GCPOrgID != "" || incoming.OrgSettings.WorkspaceURL != "" || incoming.OrgSettings.MountRules != nil {
		// Preserve fields that the caller did not provide.
		merged := p.OrgSettings
		if incoming.OrgSettings.OrgName != "" {
			merged.OrgName = incoming.OrgSettings.OrgName
		}
		if len(incoming.OrgSettings.AllowedSSO) > 0 {
			merged.AllowedSSO = incoming.OrgSettings.AllowedSSO
		}
		if len(incoming.OrgSettings.AdminEmails) > 0 {
			merged.AdminEmails = incoming.OrgSettings.AdminEmails
		}
		if incoming.OrgSettings.SeatLimit != 0 {
			merged.SeatLimit = incoming.OrgSettings.SeatLimit
		}
		if incoming.OrgSettings.GCPOrgID != "" {
			merged.GCPOrgID = incoming.OrgSettings.GCPOrgID
		}
		if incoming.OrgSettings.WorkspaceURL != "" {
			merged.WorkspaceURL = incoming.OrgSettings.WorkspaceURL
		}
		if incoming.OrgSettings.MountRules != nil {
			// Normalize each rule's Mode field.
			rules := make([]policy.MountRule, 0, len(incoming.OrgSettings.MountRules))
			for _, mr := range incoming.OrgSettings.MountRules {
				if strings.TrimSpace(mr.Pattern) == "" {
					continue
				}
				rules = append(rules, policy.MountRule{
					Pattern: strings.TrimSpace(mr.Pattern),
					Mode:    policy.NormalizeMountMode(mr.Mode),
				})
			}
			merged.MountRules = rules
		}
		// MountRoot is not user-writable; always pull from env var.
		merged.MountRoot = policy.MountRootFromEnv()
		p.OrgSettings = merged
	}
	// Guardrail: 부분 업데이트 (필드별로 merge). 클라이언트가 보낸 필드만 덮어씀.
	if strings.TrimSpace(incoming.Guardrail.Constitution) != "" {
		p.Guardrail.Constitution = incoming.Guardrail.Constitution
	}
	if incoming.Guardrail.G1CustomPatterns != nil {
		// 빈 패턴 제거 및 trim, mode normalize
		cleaned := make([]policy.G1CustomPattern, 0, len(incoming.Guardrail.G1CustomPatterns))
		for _, pat := range incoming.Guardrail.G1CustomPatterns {
			pattern := strings.TrimSpace(pat.Pattern)
			if pattern == "" {
				continue
			}
			mode := strings.ToLower(strings.TrimSpace(pat.Mode))
			if mode != "credential" && mode != "block" {
				mode = "block" // default to safer block mode
			}
			cleaned = append(cleaned, policy.G1CustomPattern{
				Pattern:     pattern,
				Description: strings.TrimSpace(pat.Description),
				Mode:        mode,
			})
		}
		p.Guardrail.G1CustomPatterns = cleaned
	}
	if incoming.Guardrail.G3WikiHint != "" {
		p.Guardrail.G3WikiHint = incoming.Guardrail.G3WikiHint
	}

	p.OrgID = orgID
	p.Version = s.store.NextVersion(orgID)
	p.Signature = ""
	if err := s.store.Save(&p); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{"version": p.Version})
}

func (s *Server) listVersions(w http.ResponseWriter, orgID string) {
	versions := s.store.ListVersions(orgID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(versions)
}

func (s *Server) rollbackPolicy(w http.ResponseWriter, orgID string, verStr string) {
	ver, err := strconv.Atoi(verStr)
	if err != nil {
		http.Error(w, "invalid version", http.StatusBadRequest)
		return
	}
	old, err := s.store.LoadVersion(orgID, ver)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	old.Version = s.store.NextVersion(orgID)
	old.Signature = ""
	if err := s.store.Save(old); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"rolled_back_to": ver, "new_version": old.Version})
}

func (s *Server) getSignedNetworkPolicy(w http.ResponseWriter, orgID string) {
	p, err := s.store.EnsureDefault(orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	policyDoc := map[string]any{
		"endpoints":  p.Network,
		"updated_at": p.UpdatedAt,
	}
	policyJSON, err := json.Marshal(policyDoc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sig, err := s.signer.SignBytes(policyJSON)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"policy":    json.RawMessage(policyJSON),
		"signature": sig,
	})
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
	p, err := s.store.EnsureDefault(orgID)
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

	next := *p
	if body.DisplayName != nil {
		next.OrgSettings.OrgName = strings.TrimSpace(*body.DisplayName)
	}
	if body.Settings != nil {
		if err := applyOrgSettingsPatch(&next, body.Settings); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	next.Version = s.store.NextVersion(orgID)
	next.Signature = ""
	if err := s.store.Save(&next); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
