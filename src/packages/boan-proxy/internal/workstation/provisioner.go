package workstation

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/config"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/userstore"
)

type Provisioner interface {
	Ensure(ctx context.Context, email, orgID string, current *userstore.Workstation) (*userstore.Workstation, error)
	RepairCredentials(ctx context.Context, email, orgID string, current *userstore.Workstation) (*userstore.Workstation, error)
}

type noopProvisioner struct {
	cfg *config.Config
}

func New(cfg *config.Config) Provisioner {
	if cfg.WorkstationProvider == "gcp-compute" {
		return newGCPProvisioner(cfg)
	}
	return &noopProvisioner{cfg: cfg}
}

func (p *noopProvisioner) Ensure(_ context.Context, email, _ string, current *userstore.Workstation) (*userstore.Workstation, error) {
	if current != nil && current.InstanceID != "" && current.Status != "unprovisioned" && isRealWorkstation(current) {
		return current, nil
	}
	return &userstore.Workstation{
		Provider:      safeProvider(p.cfg.WorkstationProvider),
		Platform:      safePlatform(p.cfg.WorkstationPlatform),
		Status:        "unprovisioned",
		DisplayName:   fmt.Sprintf("%s 전용 Windows 작업 컴퓨터", localPart(email)),
		InstanceID:    "",
		Region:        p.cfg.WorkstationRegion,
		ConsoleURL:    "",
		WebDesktopURL: "",
		AssignedAt:    time.Now().UTC(),
	}, nil
}

func (p *noopProvisioner) RepairCredentials(_ context.Context, email, _ string, current *userstore.Workstation) (*userstore.Workstation, error) {
	if current != nil {
		current.Status = "provisioning"
		return current, nil
	}
	return p.Ensure(context.Background(), email, "", current)
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func userSlug(email string) string {
	local := localPart(email)
	local = strings.ToLower(local)
	local = slugRe.ReplaceAllString(local, "-")
	local = strings.Trim(local, "-")
	if local == "" {
		return "user"
	}
	return local
}

func localPart(email string) string {
	parts := strings.Split(strings.TrimSpace(email), "@")
	if len(parts) == 0 || parts[0] == "" {
		return "user"
	}
	return parts[0]
}

func safeProvider(v string) string {
	if strings.TrimSpace(v) == "" {
		return "gcp-compute"
	}
	return v
}

func safePlatform(v string) string {
	if strings.TrimSpace(v) == "" {
		return "windows"
	}
	return v
}

func isRealWorkstation(ws *userstore.Workstation) bool {
	if ws == nil {
		return false
	}
	instanceID := strings.TrimSpace(ws.InstanceID)
	if instanceID == "" {
		return false
	}
	return strings.Contains(instanceID, "/instances/")
}
