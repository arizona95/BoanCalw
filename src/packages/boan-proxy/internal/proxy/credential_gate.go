package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/credential"
)

// rawAPIKeyRe matches verbatim API key tokens (extractable values without context noise).
var rawAPIKeyRe = regexp.MustCompile(`(?i)\b(?:ghp_|github_pat_|sk-[a-z0-9]{2,6}-|sk-proj-|AKIA|AIza)[A-Za-z0-9_\-]{16,}\b`)

var obviousNonSecretMarkers = []string{
	"fake",
	"test",
	"dummy",
	"example",
	"sample",
	"mock",
	"placeholder",
	"notreal",
}

func isObviouslyNonSecretCredential(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return false
	}
	for _, marker := range obviousNonSecretMarkers {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func isCredentialPassthrough(value string, passthrough map[string]struct{}) bool {
	if isObviouslyNonSecretCredential(value) {
		return true
	}
	if len(passthrough) == 0 {
		return false
	}
	_, ok := passthrough[strings.TrimSpace(value)]
	return ok
}

// credentialFingerprint returns a SHA-256 hex fingerprint of a credential value.
func credentialFingerprint(value string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(h[:])
}

// credentialPreview masks a credential value for display: first 4 + "..." + last 4.
func credentialPreview(value string) string {
	if len(value) <= 8 {
		return "****"
	}
	return value[:4] + "..." + value[len(value)-4:]
}

// declinedFingerprintStore persists SHA-256 fingerprints of credentials the user
// declined to register, so HITL is not raised again for the same value.
type declinedFingerprintStore struct {
	mu   sync.RWMutex
	fps  map[string]time.Time // fingerprint → declined_at
	path string
}

func newDeclinedFingerprintStore(dataDir string) *declinedFingerprintStore {
	s := &declinedFingerprintStore{
		fps:  make(map[string]time.Time),
		path: dataDir + "/declined_credentials.json",
	}
	_ = s.load()
	return s
}

// IsDeclined reports whether the given raw credential value has been previously declined.
func (s *declinedFingerprintStore) IsDeclined(value string) bool {
	fp := credentialFingerprint(value)
	s.mu.RLock()
	_, ok := s.fps[fp]
	s.mu.RUnlock()
	return ok
}

// AddByValue computes the fingerprint for value and persists it as declined.
func (s *declinedFingerprintStore) AddByValue(value string) {
	s.addFP(credentialFingerprint(value))
}

// AddFingerprint persists a pre-computed fingerprint as declined.
func (s *declinedFingerprintStore) AddFingerprint(fp string) {
	s.addFP(fp)
}

func (s *declinedFingerprintStore) addFP(fp string) {
	s.mu.Lock()
	s.fps[fp] = time.Now()
	s.mu.Unlock()
	_ = s.save()
}

func (s *declinedFingerprintStore) load() error {
	raw, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var items map[string]time.Time
	if err := json.Unmarshal(raw, &items); err != nil {
		return err
	}
	s.mu.Lock()
	s.fps = items
	s.mu.Unlock()
	return nil
}

func (s *declinedFingerprintStore) save() error {
	if s.path == "" {
		return nil
	}
	s.mu.RLock()
	raw, err := json.MarshalIndent(s.fps, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, raw, 0600)
}

// credGateResult holds the outcome of applyCredentialGate.
type credGateResult struct {
	// Prompt is the sanitized prompt (registered credentials replaced with
	// {{CREDENTIAL:name}} placeholders; unknown ones replaced with [REDACTED]).
	Prompt string
	// HITLRequired is true when at least one unregistered, non-declined credential
	// was found. A HITL approval notification has been created in this case.
	HITLRequired bool
	// ApprovalID is the ID of the created approval record (if HITLRequired).
	ApprovalID string
}

// applyCredentialGate scans the prompt and:
//  1. Replaces known/registered credential values with {{CREDENTIAL:name}}.
//  2. Replaces remaining unknown API keys with [REDACTED].
//  3. For unknown keys that have not been previously declined, creates a HITL
//     approval via createApproval and sets HITLRequired.
//
// The prompt is always safe to forward after this call regardless of HITLRequired.
func (s *Server) applyCredentialGate(
	ctx context.Context,
	orgID, prompt string,
	createApproval func(keys []string, previews []string, fps []string) string,
) credGateResult {
	// Fast path: no API key patterns detected.
	if !rawAPIKeyRe.MatchString(prompt) {
		return credGateResult{Prompt: prompt}
	}

	// Step 1: fetch all registered credential names for this org.
	names := s.fetchCredentialNames(ctx, orgID)
	passthrough := s.credentialPassthroughValues(orgID)

	replaced := prompt

	// Step 2: replace registered credential values with {{CREDENTIAL:name}}.
	for _, name := range names {
		val, err := credential.Resolve(ctx, s.cfg.CredentialFilterURL, orgID, name)
		if err != nil || strings.TrimSpace(val) == "" {
			continue
		}
		if strings.Contains(replaced, val) {
			replaced = strings.ReplaceAll(replaced, val, fmt.Sprintf("{{CREDENTIAL:%s}}", name))
		}
	}

	// Step 3: detect remaining raw API keys after registered replacements.
	remaining := rawAPIKeyRe.FindAllString(replaced, -1)
	if len(remaining) == 0 {
		return credGateResult{Prompt: replaced}
	}

	// Deduplicate remaining keys.
	seen := map[string]struct{}{}
	unique := remaining[:0]
	for _, k := range remaining {
		if _, ok := seen[k]; !ok {
			seen[k] = struct{}{}
			unique = append(unique, k)
		}
	}
	remaining = unique

	// Step 4: separate declined vs new unknown keys; redact all of them.
	var newKeys, newPreviews, newFPs []string
	for _, key := range remaining {
		if isCredentialPassthrough(key, passthrough) {
			continue
		}
		replaced = strings.ReplaceAll(replaced, key, "[REDACTED]")
		if !s.declinedFPs.IsDeclined(key) {
			newKeys = append(newKeys, key)
			newPreviews = append(newPreviews, credentialPreview(key))
			newFPs = append(newFPs, credentialFingerprint(key))
		}
	}

	if len(newKeys) == 0 {
		// All unknowns are already declined — just forward the redacted prompt silently.
		return credGateResult{Prompt: replaced}
	}

	// Step 5: create HITL approval for the new/unseen keys.
	approvalID := ""
	if createApproval != nil {
		approvalID = createApproval(newKeys, newPreviews, newFPs)
	}

	return credGateResult{
		Prompt:       replaced,
		HITLRequired: true,
		ApprovalID:   approvalID,
	}
}

// fetchCredentialNames returns all credential role names registered for orgID.
func (s *Server) fetchCredentialNames(ctx context.Context, orgID string) []string {
	if s.cfg.CredentialFilterURL == "" {
		return nil
	}
	url := strings.TrimRight(s.cfg.CredentialFilterURL, "/") + "/credential/" + orgID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var items []struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return nil
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		if item.Role != "" {
			names = append(names, item.Role)
		}
	}
	return names
}
