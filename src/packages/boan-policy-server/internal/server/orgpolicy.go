package server

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/samsung-sds/boanclaw/boan-policy-server/internal/policy"
)

// OrgPolicy is the single API for reading, mutating, and broadcasting org
// policy state. All policy slices (network allowlist, guardrail patterns,
// constitution, org settings, RBAC, etc.) share one persistence layer
// (policy.Store) and one push channel (broker → SSE). Callers describe their
// intent with a PolicyPatch and the dispatcher routes each non-nil field
// into the right merge code path; this keeps every mutation (HTTP handler,
// agent action, scheduled cleanup, …) consistent — store write + signed
// stream fan-out + system-endpoint reinjection happen in one place.
//
// Why pointers in PolicyPatch: distinguishes "field not present in caller's
// request" (leave existing) from "field explicitly set to empty/zero"
// (clear it). map/slice value alone can't make that distinction.
type OrgPolicy struct{ s *Server }

func newOrgPolicy(s *Server) *OrgPolicy { return &OrgPolicy{s: s} }

// PolicyPatch describes a partial update. Only non-nil fields are applied.
// Each field corresponds to one logical section the UI / agent can edit
// independently — adding more sections (e.g. RBAC roles, version pinning)
// is a matter of extending this struct and ApplyTo.
type PolicyPatch struct {
	NetworkWhitelist    *[]policy.NetworkEndpoint  `json:"network_whitelist,omitempty"`
	GT1Patterns         *[]policy.GT1Pattern       `json:"g1_custom_patterns,omitempty"`
	GT2Constitution     *string                    `json:"constitution,omitempty"`
	GT3WikiHint         *string                    `json:"g3_wiki_hint,omitempty"`
	GI1Forbidden        *[]policy.GI1ForbiddenImage `json:"gi1_forbidden,omitempty"`
	GI1HammingThreshold *int                       `json:"gi1_hamming_threshold,omitempty"`
	GI2Descriptions     *[]policy.GI2Description   `json:"gi2_descriptions,omitempty"`
	OrgSettings         *policy.OrgSettings        `json:"org_settings,omitempty"`
	DLPRules            *[]policy.DLPRule          `json:"dlp_rules,omitempty"`
	RBAC                *policy.RBACConfig         `json:"rbac,omitempty"`
	VersionPolicy       *policy.VersionPolicy      `json:"version_policy,omitempty"`
}

// Get returns the current effective policy (DB + injected system endpoints).
// Signature is recomputed so subscribers can verify the payload end-to-end.
func (op *OrgPolicy) Get(_ context.Context, orgID string) (*policy.Policy, error) {
	p, err := op.s.store.EnsureDefault(orgID)
	if err != nil {
		return nil, err
	}
	p.Network = op.s.withSystemEndpoints(p.Network)
	p.Signature = ""
	sig, _ := op.s.signer.Sign(p)
	p.Signature = sig
	return p, nil
}

// Update merges PolicyPatch into the current policy, persists, and publishes
// the signed network slice via SSE. Returns the new full policy with bumped
// version. validate() rejects malformed regex / port ranges before save so
// the store never holds a payload that crashes the gate on the device side.
func (op *OrgPolicy) Update(ctx context.Context, orgID string, patch PolicyPatch) (*policy.Policy, error) {
	if err := patch.validate(); err != nil {
		return nil, err
	}
	existing, err := op.s.store.EnsureDefault(orgID)
	if err != nil {
		return nil, err
	}
	merged := *existing
	patch.applyTo(&merged, op.s)

	merged.OrgID = orgID
	merged.Version = op.s.store.NextVersion(orgID)
	merged.Signature = ""
	if err := op.s.store.Save(&merged); err != nil {
		return nil, err
	}
	op.s.publishPolicyUpdate(orgID)

	// Re-inject system endpoints + re-sign on the way out so the caller gets
	// the same view that SSE subscribers receive (no client surprise where
	// the wire format on the stream differs from what UpdatePolicy returns).
	merged.Network = op.s.withSystemEndpoints(merged.Network)
	merged.Signature = ""
	sig, _ := op.s.signer.Sign(&merged)
	merged.Signature = sig
	return &merged, nil
}

// validate runs cheap structural checks that don't need policy context.
// Heavy checks (e.g. host reachability) belong elsewhere. Returns the first
// problem found — UI gets one clear error per save attempt.
func (p PolicyPatch) validate() error {
	if p.NetworkWhitelist != nil {
		for i, ep := range *p.NetworkWhitelist {
			if strings.TrimSpace(ep.Host) == "" {
				return fmt.Errorf("network_whitelist[%d]: host empty", i)
			}
			for _, port := range ep.Ports {
				if port < 1 || port > 65535 {
					return fmt.Errorf("network_whitelist[%d]: invalid port %d (1-65535)", i, port)
				}
			}
		}
	}
	if p.GT1Patterns != nil {
		for i, pat := range *p.GT1Patterns {
			if strings.TrimSpace(pat.Pattern) == "" {
				return fmt.Errorf("g1_custom_patterns[%d]: pattern empty", i)
			}
			if _, err := regexp.Compile(pat.Pattern); err != nil {
				return fmt.Errorf("g1_custom_patterns[%d]: invalid regex %q: %w", i, pat.Pattern, err)
			}
			if pat.Mode != "" && pat.Mode != "block" && pat.Mode != "mask" && pat.Mode != "fake" && pat.Mode != "credential" && pat.Mode != "redact" {
				return fmt.Errorf("g1_custom_patterns[%d]: unknown mode %q (block|mask|fake|credential)", i, pat.Mode)
			}
		}
	}
	if p.OrgSettings != nil && p.OrgSettings.MountRules != nil {
		for i, r := range *&p.OrgSettings.MountRules {
			if strings.TrimSpace(r.Pattern) == "" {
				continue
			}
			if _, err := regexp.Compile(r.Pattern); err != nil {
				return fmt.Errorf("org_settings.mount_rules[%d]: invalid regex %q: %w", i, r.Pattern, err)
			}
		}
	}
	return nil
}

// applyTo writes each non-nil patch field into the target Policy. The
// network whitelist gets system-endpoint stripping (Update reinjects on
// read) so admins can't sneak sys-host entries into persistent storage.
// G1 / mount-rule lists are normalized (whitespace trim, mode default).
func (p PolicyPatch) applyTo(dst *policy.Policy, s *Server) {
	if p.NetworkWhitelist != nil {
		dst.Network = s.stripSystemEndpoints(*p.NetworkWhitelist)
	}
	if p.GT1Patterns != nil {
		cleaned := make([]policy.GT1Pattern, 0, len(*p.GT1Patterns))
		for _, pat := range *p.GT1Patterns {
			pattern := strings.TrimSpace(pat.Pattern)
			if pattern == "" {
				continue
			}
			mode := strings.ToLower(strings.TrimSpace(pat.Mode))
			// legacy 'redact' → 'mask'.
			if mode == "redact" {
				mode = "mask"
			}
			if mode != "credential" && mode != "block" && mode != "fake" {
				mode = "mask"
			}
			cleaned = append(cleaned, policy.GT1Pattern{
				Pattern:     pattern,
				Description: strings.TrimSpace(pat.Description),
				Mode:        mode,
				Replacement: pat.Replacement,
			})
		}
		dst.Guardrail.GT1Patterns = cleaned
	}
	if p.GT2Constitution != nil {
		dst.Guardrail.GT2Constitution = *p.GT2Constitution
	}
	if p.GT3WikiHint != nil {
		dst.Guardrail.GT3WikiHint = *p.GT3WikiHint
	}
	if p.GI1Forbidden != nil {
		cleaned := make([]policy.GI1ForbiddenImage, 0, len(*p.GI1Forbidden))
		seen := map[string]bool{}
		for _, img := range *p.GI1Forbidden {
			h := strings.ToLower(strings.TrimSpace(img.Hash))
			if len(h) != 16 || seen[h] {
				continue
			}
			seen[h] = true
			cleaned = append(cleaned, policy.GI1ForbiddenImage{
				Hash:        h,
				Description: strings.TrimSpace(img.Description),
				UploadedAt:  img.UploadedAt,
				Replacement: img.Replacement,
			})
		}
		dst.Guardrail.GI1Forbidden = cleaned
	}
	if p.GI1HammingThreshold != nil {
		t := *p.GI1HammingThreshold
		if t < 0 {
			t = 0
		}
		if t > 64 {
			t = 64
		}
		dst.Guardrail.GI1HammingThreshold = t
	}
	if p.GI2Descriptions != nil {
		cleaned := make([]policy.GI2Description, 0, len(*p.GI2Descriptions))
		for _, d := range *p.GI2Descriptions {
			desc := strings.TrimSpace(d.Description)
			if desc == "" {
				continue
			}
			action := strings.ToLower(strings.TrimSpace(d.Action))
			if action != "block" {
				action = "ask"
			}
			cleaned = append(cleaned, policy.GI2Description{Description: desc, Action: action})
		}
		dst.Guardrail.GI2Descriptions = cleaned
	}
	if p.DLPRules != nil {
		dst.DLPRules = *p.DLPRules
	}
	if p.RBAC != nil {
		dst.RBAC = *p.RBAC
	}
	if p.VersionPolicy != nil {
		dst.VersionPolicy = *p.VersionPolicy
	}
	if p.OrgSettings != nil {
		merged := dst.OrgSettings
		incoming := *p.OrgSettings
		if incoming.OrgName != "" {
			merged.OrgName = incoming.OrgName
		}
		if len(incoming.AllowedSSO) > 0 {
			merged.AllowedSSO = incoming.AllowedSSO
		}
		if len(incoming.AdminEmails) > 0 {
			merged.AdminEmails = incoming.AdminEmails
		}
		if incoming.SeatLimit != 0 {
			merged.SeatLimit = incoming.SeatLimit
		}
		if incoming.GCPOrgID != "" {
			merged.GCPOrgID = incoming.GCPOrgID
		}
		if incoming.WorkspaceURL != "" {
			merged.WorkspaceURL = incoming.WorkspaceURL
		}
		if incoming.MountRules != nil {
			rules := make([]policy.MountRule, 0, len(incoming.MountRules))
			for _, mr := range incoming.MountRules {
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
		merged.MountRoot = policy.MountRootFromEnv()
		dst.OrgSettings = merged
	}
}

// Validation surface — used by upstream Update so callers can pre-flight.
var (
	ErrPatchEmpty = errors.New("orgpolicy: patch has no fields set")
)

// IsEmpty returns true if no field is set. Mutation handlers can fast-fail
// to 400 instead of bumping the policy version on a no-op write.
func (p PolicyPatch) IsEmpty() bool {
	return p.NetworkWhitelist == nil && p.GT1Patterns == nil && p.GT2Constitution == nil &&
		p.GT3WikiHint == nil && p.GI1Forbidden == nil && p.GI1HammingThreshold == nil &&
		p.GI2Descriptions == nil && p.OrgSettings == nil && p.DLPRules == nil &&
		p.RBAC == nil && p.VersionPolicy == nil
}

// Rollback restores an earlier saved policy version as the new head version.
// Same store.Save + broker.Publish path as Update — no other code should
// implement its own "reset to version N" shortcut. Returns the new policy
// at the bumped version with system endpoints + signature reapplied.
func (op *OrgPolicy) Rollback(_ context.Context, orgID string, version int) (*policy.Policy, error) {
	old, err := op.s.store.LoadVersion(orgID, version)
	if err != nil {
		return nil, err
	}
	old.Version = op.s.store.NextVersion(orgID)
	old.Signature = ""
	if err := op.s.store.Save(old); err != nil {
		return nil, err
	}
	op.s.publishPolicyUpdate(orgID)
	old.Network = op.s.withSystemEndpoints(old.Network)
	old.Signature = ""
	sig, _ := op.s.signer.Sign(old)
	old.Signature = sig
	return old, nil
}
