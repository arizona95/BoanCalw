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
