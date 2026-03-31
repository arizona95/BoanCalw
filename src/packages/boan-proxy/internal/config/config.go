package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Config struct {
	Listen      string        `json:"listen"`
	AdminListen string        `json:"admin_listen"`
	OrgID       string        `json:"org_id"`
	PolicyURL   string        `json:"policy_url"`
	PolicyTTL   time.Duration `json:"policy_ttl"`
	AuditEndpoint string      `json:"audit_endpoint"`
	TLSCACert   string        `json:"tls_ca_cert"`
	TLSCAKey    string        `json:"tls_ca_key"`
	LocalLLMURL string        `json:"local_llm_url"`
	SecurityAgentURL string   `json:"security_agent_url"`
	UsabilityAgentURL string  `json:"usability_agent_url"`
	ClientCertFile      string `json:"client_cert_file"`
	ClientKeyFile       string `json:"client_key_file"`
	ServerCAPemFile     string `json:"server_ca_pem_file"`
	NetworkPolicyPubKey string `json:"network_policy_pubkey"`
	LLMRegistryURL      string `json:"llm_registry_url"`
	CredentialFilterURL string `json:"credential_filter_url"`
	OAuthClientID       string `json:"oauth_client_id"`
	OAuthClientSecret   string `json:"oauth_client_secret"`
	OAuthRedirectURL    string `json:"oauth_redirect_url"`
	AppBaseURL          string `json:"app_base_url"`
	AllowedEmailDomains string `json:"allowed_email_domains"`
	OwnerEmail          string `json:"owner_email"`
	JWTSecret           string `json:"jwt_secret"`
	GCPOrgID            string `json:"gcp_org_id"`
	AdminPassword       string `json:"admin_password"`
	AdminEmails         string `json:"admin_emails"`
	AllowedSSO          string `json:"allowed_sso"`
	UserDataDir         string `json:"user_data_dir"`
	SMTPHost            string `json:"smtp_host"`
	SMTPPort            string `json:"smtp_port"`
	SMTPUser            string `json:"smtp_user"`
	SMTPPassword        string `json:"smtp_password"`
	SMTPFrom            string `json:"smtp_from"`
}

func Load() (*Config, error) {
	cfg := &Config{
		Listen:        env("BOAN_LISTEN", ":18080"),
		AdminListen:   env("BOAN_ADMIN_LISTEN", ":18081"),
		OrgID:         env("BOAN_ORG_ID", ""),
		PolicyURL:     env("BOAN_POLICY_URL", ""),
		PolicyTTL:     60 * time.Second,
		AuditEndpoint: env("BOAN_AUDIT_ENDPOINT", ""),
		TLSCACert:     env("BOAN_CA_CERT", "/etc/boan/ca.crt"),
		TLSCAKey:      env("BOAN_CA_KEY", "/etc/boan/ca.key"),
		LocalLLMURL:       env("BOAN_LOCAL_LLM_URL", "http://localhost:11434"),
		SecurityAgentURL:  env("BOAN_SECURITY_AGENT", "http://boan-agent:8080"),
		UsabilityAgentURL: env("BOAN_USABILITY_AGENT", ""),
		ClientCertFile:      env("BOAN_CLIENT_CERT", ""),
		ClientKeyFile:       env("BOAN_CLIENT_KEY", ""),
		ServerCAPemFile:     env("BOAN_SERVER_CA", ""),
		NetworkPolicyPubKey: env("BOAN_NETWORK_POLICY_PUBKEY", ""),
		LLMRegistryURL:      env("BOAN_LLM_REGISTRY_URL", "http://boan-llm-registry:8086"),
		CredentialFilterURL: env("BOAN_CREDENTIAL_FILTER_URL", "http://boan-credential-filter:8082"),
		OAuthClientID:       env("BOAN_OAUTH_CLIENT_ID", ""),
		OAuthClientSecret:   env("BOAN_OAUTH_CLIENT_SECRET", ""),
		OAuthRedirectURL:    env("BOAN_OAUTH_REDIRECT_URL", ""),
		AppBaseURL:          env("BOAN_APP_BASE_URL", ""),
		AllowedEmailDomains: env("BOAN_ALLOWED_EMAIL_DOMAINS", ""),
		OwnerEmail:          env("BOAN_OWNER_EMAIL", ""),
		JWTSecret:           env("BOAN_JWT_SECRET", ""),
		GCPOrgID:            env("BOAN_GCP_ORG_ID", ""),
		AdminPassword:       env("BOAN_ADMIN_PASSWORD", "boan-admin"),
		AdminEmails:         env("BOAN_ADMIN_EMAILS", ""),
		AllowedSSO:          env("BOAN_ALLOWED_SSO", ""),
		UserDataDir:         env("BOAN_USER_DATA_DIR", "/data/users"),
		SMTPHost:            env("BOAN_SMTP_HOST", ""),
		SMTPPort:            env("BOAN_SMTP_PORT", "587"),
		SMTPUser:            env("BOAN_SMTP_USER", ""),
		SMTPPassword:        env("BOAN_SMTP_PASSWORD", ""),
		SMTPFrom:            env("BOAN_SMTP_FROM", ""),
	}

	if f := os.Getenv("BOAN_CONFIG"); f != "" {
		raw, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("read config file: %w", err)
		}
		if err := json.Unmarshal(raw, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	if cfg.OrgID == "" {
		return nil, fmt.Errorf("BOAN_ORG_ID is required")
	}
	return cfg, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
