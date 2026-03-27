package config

import (
	"encoding/json"
	"os"
	"strconv"
)

type Config struct {
	Listen          string
	CredFilterURL   string
	OrgID           string
	ModelMap        map[string]string
	RateLimitRPM    int
	UpstreamBaseURL string
	CredentialName  string
	CredentialType  string
}

func Load() *Config {
	cfg := &Config{
		Listen:          getEnv("BOAN_ONECLI_LISTEN", ":8083"),
		CredFilterURL:   getEnv("BOAN_ONECLI_CRED_FILTER_URL", "http://boan-credential-filter:8082"),
		OrgID:           getEnv("BOAN_ONECLI_ORG_ID", "default"),
		RateLimitRPM:    getEnvInt("BOAN_ONECLI_RATE_LIMIT_RPM", 60),
		UpstreamBaseURL: getEnv("BOAN_ONECLI_UPSTREAM_URL", "https://api.anthropic.com"),
		CredentialName:  getEnv("BOAN_ONECLI_CREDENTIAL_NAME", ""),
		CredentialType:  getEnv("BOAN_ONECLI_CREDENTIAL_TYPE", "api_key"),
		ModelMap:        map[string]string{},
	}

	if raw := os.Getenv("BOAN_ONECLI_MODEL_MAP"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg.ModelMap)
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
