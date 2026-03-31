package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/roles"
)

var RoleLabel = roles.Labels

type Session struct {
	Sub   string     `json:"sub"`
	Email string     `json:"email"`
	Name  string     `json:"name"`
	Role  roles.Role `json:"role"`
	OrgID string     `json:"org_id"`
	Exp   int64      `json:"exp"`
}

type Config struct {
	ClientID            string
	ClientSecret        string
	RedirectURL         string
	AppBaseURL          string
	AllowedEmailDomains []string
	JWTSecret           string
	GCPOrgID            string
}

type Provider struct {
	cfg    Config
	secret []byte
	client *http.Client
}

func New(cfg Config) *Provider {
	if cfg.JWTSecret == "" {
		b := make([]byte, 32)
		rand.Read(b)
		cfg.JWTSecret = base64.RawURLEncoding.EncodeToString(b)
	}
	return &Provider{
		cfg:    cfg,
		secret: []byte(cfg.JWTSecret),
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *Provider) Enabled() bool {
	return p.cfg.ClientID != "" && p.cfg.ClientSecret != ""
}

func (p *Provider) AuthURL(state, redirectURL string) string {
	if redirectURL == "" {
		redirectURL = p.cfg.RedirectURL
	}
	v := url.Values{}
	v.Set("client_id", p.cfg.ClientID)
	v.Set("redirect_uri", redirectURL)
	v.Set("response_type", "code")
	v.Set("scope", "openid email profile")
	v.Set("state", state)
	v.Set("access_type", "online")
	if hd := p.HostedDomain(); hd != "" {
		v.Set("hd", hd)
	}
	return "https://accounts.google.com/o/oauth2/v2/auth?" + v.Encode()
}

func (p *Provider) ExchangeCode(code, redirectURL string) (string, error) {
	if redirectURL == "" {
		redirectURL = p.cfg.RedirectURL
	}
	v := url.Values{}
	v.Set("code", code)
	v.Set("client_id", p.cfg.ClientID)
	v.Set("client_secret", p.cfg.ClientSecret)
	v.Set("redirect_uri", redirectURL)
	v.Set("grant_type", "authorization_code")
	resp, err := p.client.PostForm("https://oauth2.googleapis.com/token", v)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tok struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", err
	}
	if tok.Error != "" {
		return "", fmt.Errorf("token exchange: %s", tok.Error)
	}
	return tok.AccessToken, nil
}

type UserInfo struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

func (p *Provider) GetUserInfo(accessToken string) (*UserInfo, error) {
	req, _ := http.NewRequest(http.MethodGet, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var u UserInfo
	return &u, json.NewDecoder(resp.Body).Decode(&u)
}

type GCPOrg struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	State       string `json:"state"`
	OrgID       string
}

func (p *Provider) FindUserOrgs(accessToken string) ([]GCPOrg, error) {
	req, err := http.NewRequest(http.MethodPost,
		"https://cloudresourcemanager.googleapis.com/v3/organizations:search",
		strings.NewReader("{}"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result struct {
		Organizations []struct {
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
			State       string `json:"state"`
		} `json:"organizations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	orgs := make([]GCPOrg, 0, len(result.Organizations))
	for _, o := range result.Organizations {
		id := strings.TrimPrefix(o.Name, "organizations/")
		orgs = append(orgs, GCPOrg{
			Name:        o.Name,
			DisplayName: o.DisplayName,
			State:       o.State,
			OrgID:       id,
		})
	}
	return orgs, nil
}

func (p *Provider) ResolveRoleForOrg(accessToken, email, gcpOrgID string) roles.Role {
	if gcpOrgID == "" {
		return roles.User
	}
	policyURL := "https://cloudresourcemanager.googleapis.com/v1/organizations/" +
		gcpOrgID + ":getIamPolicy"
	req, err := http.NewRequest(http.MethodPost, policyURL, strings.NewReader("{}"))
	if err != nil {
		return roles.User
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return roles.User
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var policy struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		return roles.User
	}
	member := "user:" + email
	for _, b := range policy.Bindings {
		for _, m := range b.Members {
			if m != member {
				continue
			}
			switch b.Role {
			case "roles/resourcemanager.organizationAdmin", "roles/owner":
				return roles.Owner
			}
		}
	}
	return roles.User
}

func (p *Provider) ResolveRole(accessToken, email string) roles.Role {
	if p.cfg.GCPOrgID == "" {
		return roles.User
	}
	policyURL := "https://cloudresourcemanager.googleapis.com/v1/organizations/" +
		p.cfg.GCPOrgID + ":getIamPolicy"
	req, err := http.NewRequest(http.MethodPost, policyURL, strings.NewReader("{}"))
	if err != nil {
		return roles.User
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		return roles.User
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var policy struct {
		Bindings []struct {
			Role    string   `json:"role"`
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		return roles.User
	}
	member := "user:" + email
	for _, b := range policy.Bindings {
		for _, m := range b.Members {
			if m != member {
				continue
			}
			switch b.Role {
			case "roles/resourcemanager.organizationAdmin", "roles/owner":
				return roles.Owner
			}
		}
	}
	return roles.User
}

type OAuthState struct {
	RedirectURL string `json:"redirect_url"`
	ReturnTo    string `json:"return_to"`
	IssuedAt    int64  `json:"issued_at"`
}

func (p *Provider) CreateStateToken(st *OAuthState) (string, error) {
	payload, err := json.Marshal(st)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return body + "." + p.sign(body), nil
}

func (p *Provider) ParseStateToken(token string) (*OAuthState, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid state")
	}
	if !hmac.Equal([]byte(parts[1]), []byte(p.sign(parts[0]))) {
		return nil, fmt.Errorf("invalid state signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var st OAuthState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func (p *Provider) HostedDomain() string {
	if len(p.cfg.AllowedEmailDomains) == 0 {
		return ""
	}
	return p.cfg.AllowedEmailDomains[0]
}

func (p *Provider) ValidateEmailDomain(email string) bool {
	if len(p.cfg.AllowedEmailDomains) == 0 {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	for _, allowed := range p.cfg.AllowedEmailDomains {
		if domain == strings.ToLower(strings.TrimSpace(allowed)) {
			return true
		}
	}
	return false
}

func (p *Provider) CreateToken(s *Session) (string, error) {
	s.Exp = time.Now().Add(8 * time.Hour).Unix()
	payload, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString(payload)
	sig := p.sign(header + "." + body)
	return header + "." + body + "." + sig, nil
}

func (p *Provider) ParseToken(token string) (*Session, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token")
	}
	expected := p.sign(parts[0] + "." + parts[1])
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil, fmt.Errorf("invalid signature")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if time.Now().Unix() > s.Exp {
		return nil, fmt.Errorf("token expired")
	}
	return &s, nil
}

func (p *Provider) sign(data string) string {
	mac := hmac.New(sha256.New, p.secret)
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func SessionFromRequest(r *http.Request, prov *Provider) (*Session, error) {
	cookie, err := r.Cookie("boan_session")
	if err != nil {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			return nil, fmt.Errorf("no session")
		}
		return prov.ParseToken(strings.TrimPrefix(auth, "Bearer "))
	}
	return prov.ParseToken(cookie.Value)
}

func CanEdit(role roles.Role) bool {
	return roles.CanEdit(role)
}
