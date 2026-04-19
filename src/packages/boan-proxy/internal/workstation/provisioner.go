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
	// Delete — 사용자의 GCP VM 을 즉시 삭제. user 가 owner 에 의해 제거될 때 호출.
	// noop provider 는 빈 구현. error 는 caller 가 best-effort 로 로그만 찍을 수 있음.
	Delete(ctx context.Context, email, orgID string, current *userstore.Workstation) error
	// CaptureGoldenImage — 현재 VM 을 GCP Custom Image 로 스냅샷.
	// 흐름: STOP → disks.createImage → START. 생성된 이미지 URI 반환
	// (예: projects/{proj}/global/images/{name}). 이 URI 를 org settings 에
	// 저장해두면 신규 사용자 VM 이 이 이미지로 프로비저닝된다.
	// noop provider 는 ErrGoldenImageUnsupported 반환.
	CaptureGoldenImage(ctx context.Context, current *userstore.Workstation, imageName, description string) (string, error)

	// IsolateNetwork — kill chain 첫 단계. VM 에 "boan-quarantine" network tag 를
	// 추가해 사전 설치된 deny-all egress firewall rule 에 걸리게 한다.
	// VM 은 계속 running 상태라 RAM dump / disk snapshot 은 가능하지만 외부와
	// 의 통신은 모두 차단된다.
	// noop provider 는 ErrKillChainUnsupported 반환.
	IsolateNetwork(ctx context.Context, current *userstore.Workstation) error

	// ForensicDiskSnapshot — incident 용 disk snapshot (CaptureGoldenImage 과
	// 동일 GCP API 지만 이름/라벨로 구분: 포렌식 용 image 로 라벨링).
	// 반환: image URI. 실패해도 kill chain 다음 단계는 계속 진행해야 함.
	ForensicDiskSnapshot(ctx context.Context, current *userstore.Workstation, incidentID string) (string, error)

	// StopInstance — VM 전원 끔. RAM 증발. disk 는 유지.
	StopInstance(ctx context.Context, current *userstore.Workstation) error
}

// ErrKillChainUnsupported — non-GCP provisioner 에서 kill chain 호출 시.
var ErrKillChainUnsupported = fmt.Errorf("kill chain only supported on gcp-compute provisioner")

// ErrGoldenImageUnsupported — non-GCP provisioner 에서 이미지 기능 호출 시.
var ErrGoldenImageUnsupported = fmt.Errorf("golden image capture only supported on gcp-compute provisioner")

// AttachGoldenImageResolver — provisioner 가 gcp-compute 이면 resolver 를 붙인다.
// 그 외 provider 는 no-op. server 가 orgSettings 를 읽어오는 콜백을 넘긴다.
func AttachGoldenImageResolver(prov Provisioner, resolver GoldenImageResolver) {
	if gcp, ok := prov.(*gcpProvisioner); ok {
		gcp.ResolveGoldenImage = resolver
	}
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

func (p *noopProvisioner) Delete(_ context.Context, _, _ string, _ *userstore.Workstation) error {
	// noop provider — 실제 VM 이 없으므로 할 일 없음.
	return nil
}

func (p *noopProvisioner) CaptureGoldenImage(_ context.Context, _ *userstore.Workstation, _, _ string) (string, error) {
	return "", ErrGoldenImageUnsupported
}

func (p *noopProvisioner) IsolateNetwork(_ context.Context, _ *userstore.Workstation) error {
	return ErrKillChainUnsupported
}

func (p *noopProvisioner) ForensicDiskSnapshot(_ context.Context, _ *userstore.Workstation, _ string) (string, error) {
	return "", ErrKillChainUnsupported
}

func (p *noopProvisioner) StopInstance(_ context.Context, _ *userstore.Workstation) error {
	return ErrKillChainUnsupported
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
