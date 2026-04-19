package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Listen                    string        `json:"listen"`
	AdminListen               string        `json:"admin_listen"`
	TestMode                  bool          `json:"test_mode"`
	OrgID                     string        `json:"org_id"`
	PolicyURL                 string        `json:"policy_url"`
	OrgToken                  string        `json:"org_token"`
	// PolicyURLPattern: 조직 ID → policy-server URL 자동 해석 공식.
	// 사용자가 org_id 만 입력하면 proxy 가 이걸로 URL 조립.
	// 기본값은 현재 GCP 프로젝트 구조. 다른 프로젝트면 install 시 override.
	// "{org_id}" 또는 "%s" 를 조직 ID 자리표시자로 씀.
	PolicyURLPattern          string        `json:"policy_url_pattern"`
	PolicyTTL                 time.Duration `json:"policy_ttl"`
	AuditEndpoint             string        `json:"audit_endpoint"`
	TLSCACert                 string        `json:"tls_ca_cert"`
	TLSCAKey                  string        `json:"tls_ca_key"`
	LocalLLMURL               string        `json:"local_llm_url"`
	LocalLLMModel             string        `json:"local_llm_model"`
	SecurityAgentURL          string        `json:"security_agent_url"`
	UsabilityAgentURL         string        `json:"usability_agent_url"`
	ClientCertFile            string        `json:"client_cert_file"`
	ClientKeyFile             string        `json:"client_key_file"`
	ServerCAPemFile           string        `json:"server_ca_pem_file"`
	NetworkPolicyPubKey       string        `json:"network_policy_pubkey"`
	LLMRegistryURL            string        `json:"llm_registry_url"`
	CredentialFilterURL       string        `json:"credential_filter_url"`
	OrgLLMProxyURL            string        `json:"org_llm_proxy_url"`
	OrgLLMProxyToken          string        `json:"org_llm_proxy_token"`
	OrgLLMProxyBypassHosts    string        `json:"org_llm_proxy_bypass_hosts"`
	DeviceKeyPath             string        `json:"device_key_path"`
	OAuthClientID             string        `json:"oauth_client_id"`
	OAuthClientSecret         string        `json:"oauth_client_secret"`
	OAuthRedirectURL          string        `json:"oauth_redirect_url"`
	AppBaseURL                string        `json:"app_base_url"`
	AllowedEmailDomains       string        `json:"allowed_email_domains"`
	OwnerEmail                string        `json:"owner_email"`
	JWTSecret                 string        `json:"jwt_secret"`
	GCPOrgID                  string        `json:"gcp_org_id"`
	AdminPassword             string        `json:"admin_password"`
	AdminEmails               string        `json:"admin_emails"`
	AllowedSSO                string        `json:"allowed_sso"`
	UserDataDir               string        `json:"user_data_dir"`
	SMTPHost                  string        `json:"smtp_host"`
	SMTPPort                  string        `json:"smtp_port"`
	SMTPUser                  string        `json:"smtp_user"`
	SMTPPassword              string        `json:"smtp_password"`
	SMTPFrom                  string        `json:"smtp_from"`
	WorkstationProvider       string        `json:"workstation_provider"`
	WorkstationPlatform       string        `json:"workstation_platform"`
	WorkstationRegion         string        `json:"workstation_region"`
	WorkstationConsoleBaseURL string        `json:"workstation_console_base_url"`
	WorkstationWebBaseURL     string        `json:"workstation_web_base_url"`
	WorkstationMachineType    string        `json:"workstation_machine_type"`
	WorkstationProjectID      string        `json:"workstation_project_id"`
	WorkstationZone           string        `json:"workstation_zone"`
	WorkstationImageProject   string        `json:"workstation_image_project"`
	WorkstationImageFamily    string        `json:"workstation_image_family"`
	WorkstationSubnetwork     string        `json:"workstation_subnetwork"`
	WorkstationNetworkTags    string        `json:"workstation_network_tags"`
	WorkstationServiceAccount string        `json:"workstation_service_account"`
	WorkstationRootVolumeGiB  int           `json:"workstation_root_volume_gib"`
	GuacamoleURL              string        `json:"guacamole_url"`
	GuacamoleUsername         string        `json:"guacamole_username"`
	GuacamolePassword         string        `json:"guacamole_password"`
	GuacamoleBasePath         string        `json:"guacamole_base_path"`
	OpenClawGatewayToken      string        `json:"openclaw_gateway_token"`
	RDPTransferRoot           string        `json:"rdp_transfer_root"`
}

func Load() (*Config, error) {
	cfg := &Config{
		Listen:                    env("BOAN_LISTEN", ":18080"),
		AdminListen:               env("BOAN_ADMIN_LISTEN", ":18081"),
		TestMode:                  envBool("TEST", false) || envBool("BOAN_TEST_MODE", false),
		OrgID:                     env("BOAN_ORG_ID", ""),
		PolicyURL:                 env("BOAN_POLICY_URL", ""),
		OrgToken:                  env("BOAN_ORG_TOKEN", ""),
		PolicyURLPattern:          env("BOAN_POLICY_URL_PATTERN", "https://boan-policy-server-{org_id}-3avhtf4kka-du.a.run.app"),
		PolicyTTL:                 60 * time.Second,
		AuditEndpoint:             env("BOAN_AUDIT_ENDPOINT", ""),
		TLSCACert:                 env("BOAN_CA_CERT", "/etc/boan/ca.crt"),
		TLSCAKey:                  env("BOAN_CA_KEY", "/etc/boan/ca.key"),
		LocalLLMURL:               env("BOAN_LOCAL_LLM_URL", "http://localhost:11434"),
		LocalLLMModel:             env("BOAN_LOCAL_LLM_MODEL", ""),
		SecurityAgentURL:          env("BOAN_SECURITY_AGENT", "http://boan-agent:8080"),
		UsabilityAgentURL:         env("BOAN_USABILITY_AGENT", ""),
		ClientCertFile:            env("BOAN_CLIENT_CERT", ""),
		ClientKeyFile:             env("BOAN_CLIENT_KEY", ""),
		ServerCAPemFile:           env("BOAN_SERVER_CA", ""),
		NetworkPolicyPubKey:       env("BOAN_NETWORK_POLICY_PUBKEY", ""),
		LLMRegistryURL:            env("BOAN_LLM_REGISTRY_URL", "http://boan-llm-registry:8086"),
		CredentialFilterURL:       env("BOAN_CREDENTIAL_FILTER_URL", "http://boan-credential-filter:8082"),
		OrgLLMProxyURL:            env("BOAN_ORG_LLM_PROXY_URL", "http://boan-org-llm-proxy:8091"),
		OrgLLMProxyToken:          env("BOAN_ORG_LLM_PROXY_AUTH_TOKEN", ""),
		OrgLLMProxyBypassHosts:    env("BOAN_ORG_LLM_PROXY_BYPASS_HOSTS", "localhost,127.0.0.1,boan-llm-registry,boan-credential-filter,boan-policy-server,boan-guacamole,boan-sandbox,boan-proxy"),
		DeviceKeyPath:             env("BOAN_DEVICE_KEY_PATH", "/data/boan-device/identity.json"),
		OAuthClientID:             env("BOAN_OAUTH_CLIENT_ID", ""),
		OAuthClientSecret:         env("BOAN_OAUTH_CLIENT_SECRET", ""),
		OAuthRedirectURL:          env("BOAN_OAUTH_REDIRECT_URL", ""),
		AppBaseURL:                env("BOAN_APP_BASE_URL", ""),
		AllowedEmailDomains:       env("BOAN_ALLOWED_EMAIL_DOMAINS", ""),
		OwnerEmail:                env("BOAN_OWNER_EMAIL", ""),
		JWTSecret:                 env("BOAN_JWT_SECRET", ""),
		GCPOrgID:                  env("BOAN_GCP_ORG_ID", ""),
		AdminPassword:             env("BOAN_ADMIN_PASSWORD", "boan-admin"),
		AdminEmails:               env("BOAN_ADMIN_EMAILS", ""),
		AllowedSSO:                env("BOAN_ALLOWED_SSO", ""),
		UserDataDir:               env("BOAN_USER_DATA_DIR", "/data/users"),
		SMTPHost:                  env("BOAN_SMTP_HOST", ""),
		SMTPPort:                  env("BOAN_SMTP_PORT", "587"),
		SMTPUser:                  env("BOAN_SMTP_USER", ""),
		SMTPPassword:              env("BOAN_SMTP_PASSWORD", ""),
		SMTPFrom:                  env("BOAN_SMTP_FROM", ""),
		WorkstationProvider:       env("BOAN_WORKSTATION_PROVIDER", "gcp-compute"),
		WorkstationPlatform:       env("BOAN_WORKSTATION_PLATFORM", "windows"),
		WorkstationRegion:         env("BOAN_WORKSTATION_REGION", "asia-northeast3"),
		WorkstationConsoleBaseURL: env("BOAN_WORKSTATION_CONSOLE_BASE_URL", ""),
		WorkstationWebBaseURL:     env("BOAN_WORKSTATION_WEB_BASE_URL", ""),
		WorkstationMachineType:    env("BOAN_WORKSTATION_MACHINE_TYPE", "e2-standard-2"),
		WorkstationProjectID:      env("BOAN_WORKSTATION_PROJECT_ID", env("GCP_PROJECT_ID", "")),
		WorkstationZone:           env("BOAN_WORKSTATION_ZONE", "asia-northeast3-a"),
		WorkstationImageProject:   env("BOAN_WORKSTATION_IMAGE_PROJECT", "windows-cloud"),
		WorkstationImageFamily:    env("BOAN_WORKSTATION_IMAGE_FAMILY", "windows-2022"),
		WorkstationSubnetwork:     env("BOAN_WORKSTATION_SUBNETWORK", ""),
		WorkstationNetworkTags:    env("BOAN_WORKSTATION_NETWORK_TAGS", ""),
		WorkstationServiceAccount: env("BOAN_WORKSTATION_SERVICE_ACCOUNT", ""),
		WorkstationRootVolumeGiB:  envInt("BOAN_WORKSTATION_ROOT_VOLUME_GIB", 100),
		GuacamoleURL:              env("BOAN_GUACAMOLE_URL", ""),
		GuacamoleUsername:         env("BOAN_GUACAMOLE_USERNAME", ""),
		GuacamolePassword:         env("BOAN_GUACAMOLE_PASSWORD", ""),
		GuacamoleBasePath:         env("BOAN_GUACAMOLE_BASE_PATH", "/remote/"),
		OpenClawGatewayToken:      env("BOAN_OPENCLAW_GATEWAY_TOKEN", "boan-openclaw-local"),
		RDPTransferRoot:           env("BOAN_RDP_TRANSFER_ROOT", "/data/rdp-transfer"),
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

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}
