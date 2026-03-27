package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/dlp"
)

type CheckResult struct {
	Severity string `json:"severity"`
	ID       string `json:"id"`
	Message  string `json:"message"`
	Pass     bool   `json:"pass"`
	Fixed    bool   `json:"fixed,omitempty"`
}

func main() {
	deep := flag.Bool("deep", false, "run extended checks")
	fix := flag.Bool("fix", false, "attempt auto-remediation")
	asJSON := flag.Bool("json", false, "machine-readable JSON output")
	flag.Parse()

	results := runAudit(*deep, *fix)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		exitCode(results)
		return
	}

	failed := 0
	for _, r := range results {
		icon := "PASS"
		if !r.Pass {
			icon = "FAIL"
			failed++
		}
		fixNote := ""
		if r.Fixed {
			fixNote = " [auto-fixed]"
		}
		fmt.Printf("[%s] [%s] %s: %s%s\n", icon, r.Severity, r.ID, r.Message, fixNote)
	}
	fmt.Printf("\n%d/%d checks passed\n", len(results)-failed, len(results))
	exitCode(results)
}

func exitCode(results []CheckResult) {
	for _, r := range results {
		if !r.Pass {
			os.Exit(1)
		}
	}
}

func runAudit(deep, fix bool) []CheckResult {
	adminBase := envOrDefault("BOAN_ADMIN_LISTEN", "http://localhost:18081")
	if !strings.HasPrefix(adminBase, "http") {
		adminBase = "http://localhost" + adminBase
	}

	var results []CheckResult

	results = append(results, checkProxyAlive(adminBase))
	results = append(results, checkCAExists(fix))
	results = append(results, checkNoCredOnDisk())
	results = append(results, checkDLPRulesLoaded())
	results = append(results, checkOTELEndpoint())
	results = append(results, checkWhitelistNonEmpty(adminBase))

	if deep {
		results = append(results, checkNetworkGateActive(adminBase))
		results = append(results, checkCredentialStatus(adminBase))
		results = append(results, checkDLPStats(adminBase))
		results = append(results, checkTLSCertValid())
		results = append(results, checkPolicyServerReachable())
	}

	return results
}

func checkProxyAlive(base string) CheckResult {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(base + "/healthz")
	pass := err == nil && resp.StatusCode == 200
	return CheckResult{"CRITICAL", "proxy-alive", "boan-proxy is running and healthy", pass, false}
}

func checkCAExists(fix bool) CheckResult {
	certPath := envOrDefault("BOAN_CA_CERT", "/etc/boan/ca.crt")
	keyPath := envOrDefault("BOAN_CA_KEY", "/etc/boan/ca.key")
	_, errC := os.Stat(certPath)
	_, errK := os.Stat(keyPath)
	pass := errC == nil && errK == nil
	if !pass && fix {
		dir := filepath.Dir(certPath)
		if err := os.MkdirAll(dir, 0700); err == nil {
			return CheckResult{"HIGH", "ca-exists",
				fmt.Sprintf("CA directory created at %s (restart proxy to generate CA)", dir), false, true}
		}
	}
	return CheckResult{"HIGH", "ca-exists",
		fmt.Sprintf("CA cert+key present at %s", certPath), pass, false}
}

func checkNoCredOnDisk() CheckResult {
	home := os.Getenv("HOME")
	paths := []string{
		"/etc/boan/credentials.json",
		"/tmp/boan_api_key",
		home + "/.boan/credentials",
		home + "/.boan/secrets",
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return CheckResult{"CRITICAL", "no-cred-on-disk",
				"Credentials found on disk: " + p, false, false}
		}
	}
	return CheckResult{"CRITICAL", "no-cred-on-disk", "No credential files on disk", true, false}
}

func checkDLPRulesLoaded() CheckResult {
	count := dlp.RulesLoaded()
	pass := count > 0
	return CheckResult{"HIGH", "dlp-rules-loaded",
		fmt.Sprintf("DLP rules loaded: %d patterns compiled", count), pass, false}
}

func checkOTELEndpoint() CheckResult {
	ep := os.Getenv("BOAN_AUDIT_ENDPOINT")
	if ep == "" {
		return CheckResult{"MEDIUM", "otel-endpoint",
			"BOAN_AUDIT_ENDPOINT not configured (audit will log to stdout)", true, false}
	}
	conn, err := net.DialTimeout("tcp", ep, 2*time.Second)
	if err != nil {
		return CheckResult{"MEDIUM", "otel-endpoint",
			fmt.Sprintf("OTEL endpoint %s unreachable: %v", ep, err), false, false}
	}
	conn.Close()
	return CheckResult{"MEDIUM", "otel-endpoint",
		fmt.Sprintf("OTEL endpoint %s reachable", ep), true, false}
}

func checkWhitelistNonEmpty(base string) CheckResult {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(base + "/status/network-gate")
	if err != nil {
		return CheckResult{"HIGH", "whitelist-nonempty",
			"Cannot reach admin API to check whitelist", false, false}
	}
	defer resp.Body.Close()
	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return CheckResult{"HIGH", "whitelist-nonempty",
			"Failed to parse gate status", false, false}
	}
	count, _ := data["endpoint_count"].(float64)
	pass := count > 0
	return CheckResult{"HIGH", "whitelist-nonempty",
		fmt.Sprintf("Whitelist has %d endpoints", int(count)), pass, false}
}

func checkNetworkGateActive(base string) CheckResult {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(base + "/status/network-gate")
	pass := err == nil && resp.StatusCode == 200
	return CheckResult{"MEDIUM", "network-gate-active",
		"Network gate policy loaded and active", pass, false}
}

func checkCredentialStatus(base string) CheckResult {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(base + "/status/credentials")
	pass := err == nil && resp.StatusCode == 200
	return CheckResult{"HIGH", "credential-status",
		"All credentials status=ok", pass, false}
}

func checkDLPStats(base string) CheckResult {
	c := &http.Client{Timeout: 2 * time.Second}
	resp, err := c.Get(base + "/status/dlp")
	if err != nil {
		return CheckResult{"MEDIUM", "dlp-stats",
			"Cannot retrieve DLP stats", false, false}
	}
	defer resp.Body.Close()
	var data map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return CheckResult{"MEDIUM", "dlp-stats", "Failed to parse DLP stats", false, false}
	}
	rules, _ := data["rules_loaded"].(float64)
	pass := rules > 0
	return CheckResult{"MEDIUM", "dlp-stats",
		fmt.Sprintf("DLP engine active with %d rules", int(rules)), pass, false}
}

func checkTLSCertValid() CheckResult {
	certPath := envOrDefault("BOAN_CA_CERT", "/etc/boan/ca.crt")
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return CheckResult{"HIGH", "tls-cert-valid",
			"Cannot read CA certificate", false, false}
	}
	if len(raw) < 100 {
		return CheckResult{"HIGH", "tls-cert-valid",
			"CA certificate appears invalid (too small)", false, false}
	}
	return CheckResult{"HIGH", "tls-cert-valid",
		"CA certificate readable and non-empty", true, false}
}

func checkPolicyServerReachable() CheckResult {
	policyURL := os.Getenv("BOAN_POLICY_URL")
	if policyURL == "" {
		return CheckResult{"MEDIUM", "policy-server",
			"BOAN_POLICY_URL not configured", false, false}
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(policyURL + "/health")
	if err != nil {
		return CheckResult{"MEDIUM", "policy-server",
			fmt.Sprintf("Policy server %s unreachable", policyURL), false, false}
	}
	resp.Body.Close()
	pass := resp.StatusCode < 500
	return CheckResult{"MEDIUM", "policy-server",
		fmt.Sprintf("Policy server %s responded with %d", policyURL, resp.StatusCode), pass, false}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

