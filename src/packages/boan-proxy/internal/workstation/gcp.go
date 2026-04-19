package workstation

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/config"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/userstore"
)

// GoldenImageResolver — orgID 주면 해당 조직의 golden image URI 를 반환.
// URI 는 "projects/{proj}/global/images/{name}" 형식. 빈 문자열이면 사용 안 함.
type GoldenImageResolver func(orgID string) string

type gcpProvisioner struct {
	cfg          *config.Config
	client       *http.Client
	firewallOnce sync.Once
	// ResolveGoldenImage — nil 이면 무시. 설정돼 있고 결과가 non-empty 이면
	// createInstance 가 family image 대신 이 URI 를 SourceImage 로 사용.
	ResolveGoldenImage GoldenImageResolver
}

type gcpInstance struct {
	ID                any               `json:"id"`
	Name              string            `json:"name"`
	Status            string            `json:"status"`
	Labels            map[string]string `json:"labels"`
	Zone              string            `json:"zone"`
	Metadata          gcpMetadata       `json:"metadata"`
	NetworkInterfaces []gcpNIC          `json:"networkInterfaces"`
	Disks             []gcpDisk         `json:"disks"`
	Tags              gcpTags           `json:"tags"`
}

type gcpTags struct {
	Items       []string `json:"items"`
	Fingerprint string   `json:"fingerprint"`
}

type gcpDisk struct {
	Boot       bool   `json:"boot"`
	DeviceName string `json:"deviceName"`
	Source     string `json:"source"` // full URI: projects/.../zones/.../disks/{name}
}

type gcpMetadata struct {
	Fingerprint string            `json:"fingerprint"`
	Items       []gcpMetadataItem `json:"items"`
}

type gcpMetadataItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type gcpNIC struct {
	AccessConfigs []gcpAccessConfig `json:"accessConfigs"`
}

type gcpAccessConfig struct {
	NatIP string `json:"natIP"`
}

type gcpListResponse struct {
	Items []gcpInstance `json:"items"`
}

type gcpOperation struct {
	Name string `json:"name"`
}

func newGCPProvisioner(cfg *config.Config) Provisioner {
	if strings.TrimSpace(cfg.WorkstationProjectID) == "" || strings.TrimSpace(cfg.WorkstationZone) == "" {
		return &noopProvisioner{cfg: cfg}
	}

	httpClient := directHTTPClient()
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return &noopProvisioner{cfg: cfg}
	}

	return &gcpProvisioner{
		cfg:    cfg,
		client: oauth2HTTPClient(creds.TokenSource, httpClient.Transport),
	}
}

func directHTTPClient() *http.Client {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok || base == nil {
		base = &http.Transport{}
	}
	clone := base.Clone()
	// Workstation control-plane calls must not inherit the sandbox HTTP proxy,
	// otherwise token fetches degrade into blocked raw CONNECT tunnels.
	clone.Proxy = nil
	return &http.Client{Transport: clone}
}

func oauth2HTTPClient(src oauth2.TokenSource, base http.RoundTripper) *http.Client {
	if base == nil {
		base = directHTTPClient().Transport
	}
	return &http.Client{
		Transport: &oauth2.Transport{
			Source: src,
			Base:   base,
		},
	}
}

func (p *gcpProvisioner) Ensure(ctx context.Context, email, orgID string, current *userstore.Workstation) (*userstore.Workstation, error) {
	remoteUser := workstationRemoteUser(current)
	remotePass := workstationRemotePass(current)
	if remoteUser == "" {
		remoteUser = "boanclaw"
	}
	if remotePass == "" {
		remotePass = randomPassword()
	}

	// 첫 인스턴스 생성 전에 firewall rules 보장 (RDP 3389 + SSH 22)
	p.firewallOnce.Do(func() {
		if err := p.ensureFirewallRules(ctx); err != nil {
			log.Printf("[gcp-provisioner] firewall ensure failed (proceeding anyway): %v", err)
		}
	})

	instance, err := p.findExisting(ctx, email, orgID)
	if err != nil {
		return nil, err
	}
	if instance == nil {
		instance, err = p.createInstance(ctx, email, orgID, remoteUser, remotePass)
		if err != nil {
			return nil, err
		}
	} else if strings.EqualFold(instance.Status, "TERMINATED") {
		if err := p.startInstance(ctx, instance.Name); err != nil {
			return nil, err
		}
		instance.Status = "PROVISIONING"
	}
	return p.toWorkstation(email, instance, remoteUser, remotePass), nil
}

func (p *gcpProvisioner) RepairCredentials(ctx context.Context, email, orgID string, current *userstore.Workstation) (*userstore.Workstation, error) {
	instanceName := instanceNameFromCurrent(current)
	var (
		instance *gcpInstance
		err      error
	)
	if instanceName != "" {
		instance, err = p.getInstance(ctx, instanceName)
	} else {
		instance, err = p.findExisting(ctx, email, orgID)
	}
	if err != nil {
		return nil, err
	}
	if instance == nil {
		return p.Ensure(ctx, email, orgID, current)
	}

	remoteUser := workstationRemoteUser(current)
	if remoteUser == "" {
		remoteUser = "boanclaw"
	}
	remotePass := randomPassword()
	if err := p.updateStartupMetadata(ctx, instance, remoteUser, remotePass); err != nil {
		return nil, err
	}
	if err := p.restartInstance(ctx, instance.Name, instance.Status); err != nil {
		return nil, err
	}

	ws := p.toWorkstation(email, instance, remoteUser, remotePass)
	ws.Status = "provisioning"
	return ws, nil
}

func (p *gcpProvisioner) findExisting(ctx context.Context, email, orgID string) (*gcpInstance, error) {
	u := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/zones/%s/instances",
		url.PathEscape(p.cfg.WorkstationProjectID),
		url.PathEscape(p.cfg.WorkstationZone),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gcp list instances returned status %d", resp.StatusCode)
	}
	var out gcpListResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	normalizedEmail := labelValue(email)
	normalizedOrgID := labelValue(orgID)
	for _, inst := range out.Items {
		if inst.Labels["boanclaw-user-email"] == normalizedEmail && inst.Labels["boanclaw-org-id"] == normalizedOrgID {
			return &inst, nil
		}
	}
	return nil, nil
}

func (p *gcpProvisioner) getInstance(ctx context.Context, name string) (*gcpInstance, error) {
	u := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s",
		url.PathEscape(p.cfg.WorkstationProjectID),
		url.PathEscape(p.cfg.WorkstationZone),
		url.PathEscape(name),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("gcp get instance returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out gcpInstance
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (p *gcpProvisioner) createInstance(ctx context.Context, email, orgID, remoteUser, remotePass string) (*gcpInstance, error) {
	if strings.TrimSpace(p.cfg.WorkstationSubnetwork) == "" {
		return nil, fmt.Errorf("workstation_subnetwork is required; refusing to create instance on the default network")
	}

	name := fmt.Sprintf("boan-win-%s", userSlug(email))
	project := p.cfg.WorkstationProjectID
	zone := p.cfg.WorkstationZone
	region := p.cfg.WorkstationRegion
	if region == "" {
		region = regionFromZone(zone)
	}

	type diskInit struct {
		SourceImage string `json:"sourceImage"`
		DiskSizeGb  string `json:"diskSizeGb"`
		DiskType    string `json:"diskType,omitempty"`
	}
	type disk struct {
		Boot             bool     `json:"boot"`
		AutoDelete       bool     `json:"autoDelete"`
		InitializeParams diskInit `json:"initializeParams"`
	}
	type accessConfig struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	type nic struct {
		Subnetwork    string         `json:"subnetwork,omitempty"`
		AccessConfigs []accessConfig `json:"accessConfigs,omitempty"`
	}
	type metadataItem struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	type tags struct {
		Items []string `json:"items,omitempty"`
	}
	type serviceAccount struct {
		Email  string   `json:"email"`
		Scopes []string `json:"scopes"`
	}
	payload := map[string]any{
		"name":        name,
		"machineType": fmt.Sprintf("zones/%s/machineTypes/%s", zone, p.cfg.WorkstationMachineType),
		"labels": map[string]string{
			"boanclaw-managed":    "true",
			"boanclaw-user-email": labelValue(email),
			"boanclaw-org-id":     labelValue(orgID),
		},
		"disks": func() []disk {
			// golden image 가 등록돼 있으면 family 대신 그 이미지로 VM 생성.
			// 관리자 admin-install.sh 이후 "내 VM 을 골든 이미지로" 로 찍은
			// 스냅샷에는 admin 이 설치한 파일 / 폴더 / endpoint agent 가
			// 이미 들어있어서 신규 사용자가 바로 그 세팅 그대로 받는다.
			sourceImage := fmt.Sprintf("projects/%s/global/images/family/%s",
				p.cfg.WorkstationImageProject, p.cfg.WorkstationImageFamily)
			if p.ResolveGoldenImage != nil {
				if golden := strings.TrimSpace(p.ResolveGoldenImage(orgID)); golden != "" {
					sourceImage = golden
				}
			}
			return []disk{{
				Boot:       true,
				AutoDelete: true,
				InitializeParams: diskInit{
					SourceImage: sourceImage,
					DiskSizeGb:  fmt.Sprintf("%d", p.cfg.WorkstationRootVolumeGiB),
					DiskType:    fmt.Sprintf("zones/%s/diskTypes/pd-balanced", zone),
				},
			}}
		}(),
		"networkInterfaces": []nic{{
			AccessConfigs: []accessConfig{{
				Name: "External NAT",
				Type: "ONE_TO_ONE_NAT",
			}},
		}},
		"displayDevice": map[string]bool{
			"enableDisplay": true,
		},
		"metadata": map[string]any{
			"items": []metadataItem{
				{
					Key:   "windows-startup-script-ps1",
					Value: startupScript(remoteUser, remotePass),
				},
			},
		},
	}
	if subnet := strings.TrimSpace(p.cfg.WorkstationSubnetwork); subnet != "" {
		subnetwork := subnet
		if !strings.HasPrefix(subnetwork, "projects/") {
			subnetwork = fmt.Sprintf("projects/%s/regions/%s/subnetworks/%s", project, region, subnet)
		}
		payload["networkInterfaces"] = []nic{{
			Subnetwork: subnetwork,
			AccessConfigs: []accessConfig{{
				Name: "External NAT",
				Type: "ONE_TO_ONE_NAT",
			}},
		}}
	}
	tagItems := splitCSV(strings.TrimSpace(p.cfg.WorkstationNetworkTags))
	if len(tagItems) == 0 {
		tagItems = []string{"boan-workstation"}
	}
	payload["tags"] = tags{Items: tagItems}
	if sa := strings.TrimSpace(p.cfg.WorkstationServiceAccount); sa != "" {
		payload["serviceAccounts"] = []serviceAccount{{
			Email:  sa,
			Scopes: []string{"https://www.googleapis.com/auth/cloud-platform"},
		}}
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/zones/%s/instances",
		url.PathEscape(project),
		url.PathEscape(zone),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("gcp create instance returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var op gcpOperation
	_ = json.NewDecoder(resp.Body).Decode(&op)
	return &gcpInstance{
		Name:   name,
		Status: "PROVISIONING",
		Labels: map[string]string{"boanclaw-user-email": labelValue(email), "boanclaw-org-id": labelValue(orgID)},
		Zone:   fmt.Sprintf("projects/%s/zones/%s", project, zone),
	}, nil
}

// Delete — 사용자의 GCP VM 즉시 삭제. owner 가 user 를 제거할 때 호출.
// instance 이름은 current.InstanceID 또는 email 기반으로 추측.
// 이미 없으면 nil 반환 (404 = idempotent OK).
func (p *gcpProvisioner) Delete(ctx context.Context, email, _ string, current *userstore.Workstation) error {
	name := instanceNameFromCurrent(current)
	if name == "" {
		// fallback — 이메일에서 instance name 추측
		name = "boan-win-" + userSlug(email)
	}
	u := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s",
		url.PathEscape(p.cfg.WorkstationProjectID),
		url.PathEscape(p.cfg.WorkstationZone),
		url.PathEscape(name),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil // 이미 없음 — OK
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("gcp delete instance %q returned status %d: %s", name, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// stopInstance — POST /instances/{name}/stop. Image 생성 전 필수 (GCP 요구사항).
func (p *gcpProvisioner) stopInstance(ctx context.Context, name string) error {
	u := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s/stop",
		url.PathEscape(p.cfg.WorkstationProjectID),
		url.PathEscape(p.cfg.WorkstationZone),
		url.PathEscape(name),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("gcp stop instance returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// waitForInstanceStatus — 인스턴스가 targetStatus 가 될 때까지 polling. timeout 초과 시 에러.
func (p *gcpProvisioner) waitForInstanceStatus(ctx context.Context, name, targetStatus string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		inst, err := p.getInstance(ctx, name)
		if err == nil && inst != nil && strings.EqualFold(inst.Status, targetStatus) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return fmt.Errorf("instance %s did not reach status %s within %s", name, targetStatus, timeout)
}

// CaptureGoldenImage — 관리자 VM 의 boot disk 로부터 GCP Custom Image 생성.
// 흐름: STOP → disks.createImage → START. 생성된 이미지 URI 반환
// (예: projects/{proj}/global/images/{imageName}).
// imageName 빈값이면 자동 생성 (boan-golden-{instance}-{timestamp}).
func (p *gcpProvisioner) CaptureGoldenImage(ctx context.Context, current *userstore.Workstation, imageName, description string) (string, error) {
	instName := instanceNameFromCurrent(current)
	if instName == "" {
		return "", fmt.Errorf("current workstation has no instance")
	}

	// 1) instance 조회 → boot disk URI 획득
	inst, err := p.getInstance(ctx, instName)
	if err != nil {
		return "", fmt.Errorf("get instance: %w", err)
	}
	if inst == nil {
		return "", fmt.Errorf("instance %s not found", instName)
	}
	var bootDiskURI string
	for _, d := range inst.Disks {
		if d.Boot {
			bootDiskURI = d.Source
			break
		}
	}
	if bootDiskURI == "" {
		return "", fmt.Errorf("instance %s has no boot disk", instName)
	}
	// Source 는 full URI 이거나 상대경로일 수 있음 — 상대경로면 full URI 로 변환.
	if !strings.HasPrefix(bootDiskURI, "https://") && !strings.HasPrefix(bootDiskURI, "projects/") {
		bootDiskURI = fmt.Sprintf("projects/%s/zones/%s/disks/%s",
			p.cfg.WorkstationProjectID, p.cfg.WorkstationZone, bootDiskURI)
	}

	// 2) image 이름 결정
	if strings.TrimSpace(imageName) == "" {
		imageName = fmt.Sprintf("boan-golden-%s-%d", instName, time.Now().Unix())
	}
	// GCP image name constraint: lowercase, hyphens only, <63 chars.
	imageName = strings.ToLower(slugRe.ReplaceAllString(imageName, "-"))
	imageName = strings.Trim(imageName, "-")
	if len(imageName) > 62 {
		imageName = imageName[:62]
	}

	// 3) instance STOP (image 생성은 TERMINATED 상태여야 안전)
	wasRunning := strings.EqualFold(inst.Status, "RUNNING") || strings.EqualFold(inst.Status, "PROVISIONING") || strings.EqualFold(inst.Status, "STAGING")
	if wasRunning {
		if err := p.stopInstance(ctx, instName); err != nil {
			return "", fmt.Errorf("stop instance: %w", err)
		}
		if err := p.waitForInstanceStatus(ctx, instName, "TERMINATED", 3*time.Minute); err != nil {
			return "", fmt.Errorf("wait TERMINATED: %w", err)
		}
	}

	// 4) Custom Image 생성 — POST /global/images
	imagePayload := map[string]any{
		"name":        imageName,
		"sourceDisk":  bootDiskURI,
		"description": description,
		"labels": map[string]string{
			"boanclaw-golden":     "true",
			"boanclaw-source":     labelValue(instName),
		},
		// Windows image 는 shielded / secure boot 인 경우 "guestOsFeatures" 자동 복제.
	}
	imgBody, _ := json.Marshal(imagePayload)
	imgURL := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/global/images",
		url.PathEscape(p.cfg.WorkstationProjectID),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, imgURL, strings.NewReader(string(imgBody)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("create image: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("gcp createImage returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// 5) image 가 READY 될 때까지 polling (Windows disk ~5-15분)
	if err := p.waitForImageReady(ctx, imageName, 20*time.Minute); err != nil {
		// 실패해도 VM restart 는 시도
		if wasRunning {
			_ = p.startInstance(ctx, instName)
		}
		return "", fmt.Errorf("wait image ready: %w", err)
	}

	// 6) instance 재시작 (원래 돌고 있었다면)
	if wasRunning {
		if err := p.startInstance(ctx, instName); err != nil {
			return "", fmt.Errorf("restart instance after image: %w", err)
		}
	}

	imageURI := fmt.Sprintf("projects/%s/global/images/%s", p.cfg.WorkstationProjectID, imageName)
	return imageURI, nil
}

// waitForImageReady — Custom Image 상태가 READY 가 될 때까지 polling.
func (p *gcpProvisioner) waitForImageReady(ctx context.Context, imageName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	u := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/global/images/%s",
		url.PathEscape(p.cfg.WorkstationProjectID),
		url.PathEscape(imageName),
	)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
		resp, err := p.client.Do(req)
		if err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<15))
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				var obj struct {
					Status string `json:"status"`
				}
				if jerr := json.Unmarshal(body, &obj); jerr == nil {
					if strings.EqualFold(obj.Status, "READY") {
						return nil
					}
					if strings.EqualFold(obj.Status, "FAILED") {
						return fmt.Errorf("image entered FAILED state")
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(15 * time.Second):
		}
	}
	return fmt.Errorf("image %s did not become READY within %s", imageName, timeout)
}

func (p *gcpProvisioner) startInstance(ctx context.Context, name string) error {
	u := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s/start",
		url.PathEscape(p.cfg.WorkstationProjectID),
		url.PathEscape(p.cfg.WorkstationZone),
		url.PathEscape(name),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("gcp start instance returned status %d", resp.StatusCode)
	}
	return nil
}

func (p *gcpProvisioner) resetInstance(ctx context.Context, name string) error {
	u := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s/reset",
		url.PathEscape(p.cfg.WorkstationProjectID),
		url.PathEscape(p.cfg.WorkstationZone),
		url.PathEscape(name),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("gcp reset instance returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (p *gcpProvisioner) restartInstance(ctx context.Context, name, state string) error {
	switch strings.ToUpper(strings.TrimSpace(state)) {
	case "RUNNING", "PROVISIONING", "STAGING":
		return p.resetInstance(ctx, name)
	default:
		return p.startInstance(ctx, name)
	}
}

func (p *gcpProvisioner) updateStartupMetadata(ctx context.Context, instance *gcpInstance, remoteUser, remotePass string) error {
	if instance == nil {
		return fmt.Errorf("instance required")
	}
	items := make([]map[string]string, 0, len(instance.Metadata.Items)+1)
	updated := false
	for _, item := range instance.Metadata.Items {
		if item.Key == "windows-startup-script-ps1" {
			item.Value = startupScript(remoteUser, remotePass)
			updated = true
		}
		items = append(items, map[string]string{
			"key":   item.Key,
			"value": item.Value,
		})
	}
	if !updated {
		items = append(items, map[string]string{
			"key":   "windows-startup-script-ps1",
			"value": startupScript(remoteUser, remotePass),
		})
	}
	payload := map[string]any{
		"fingerprint": instance.Metadata.Fingerprint,
		"items":       items,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	u := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s/setMetadata",
		url.PathEscape(p.cfg.WorkstationProjectID),
		url.PathEscape(p.cfg.WorkstationZone),
		url.PathEscape(instance.Name),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("gcp set metadata returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (p *gcpProvisioner) toWorkstation(email string, instance *gcpInstance, remoteUser, remotePass string) *userstore.Workstation {
	instanceName := strings.TrimSpace(instance.Name)
	instanceRef := fmt.Sprintf(
		"projects/%s/zones/%s/instances/%s",
		p.cfg.WorkstationProjectID,
		p.cfg.WorkstationZone,
		instanceName,
	)
	return &userstore.Workstation{
		Provider:      safeProvider(p.cfg.WorkstationProvider),
		Platform:      safePlatform(p.cfg.WorkstationPlatform),
		Status:        gcpState(instance.Status),
		DisplayName:   fmt.Sprintf("%s 전용 Windows 작업 컴퓨터", localPart(email)),
		InstanceID:    instanceRef,
		RemoteHost:    externalIP(instance),
		RemotePort:    3389,
		RemoteUser:    remoteUser,
		RemotePass:    remotePass,
		Region:        p.cfg.WorkstationRegion,
		ConsoleURL:    renderGCPTemplate(p.cfg.WorkstationConsoleBaseURL, p.cfg.WorkstationProjectID, p.cfg.WorkstationZone, instanceName, instanceRef),
		WebDesktopURL: renderGCPTemplate(p.cfg.WorkstationWebBaseURL, p.cfg.WorkstationProjectID, p.cfg.WorkstationZone, instanceName, instanceRef),
		AssignedAt:    time.Now().UTC(),
	}
}

func gcpState(state string) string {
	switch strings.ToUpper(strings.TrimSpace(state)) {
	case "PROVISIONING", "STAGING":
		return "provisioning"
	case "RUNNING":
		return "running"
	case "STOPPING":
		return "stopping"
	case "TERMINATED":
		return "stopped"
	default:
		return "provisioning"
	}
}

func regionFromZone(zone string) string {
	parts := strings.Split(strings.TrimSpace(zone), "-")
	if len(parts) < 3 {
		return zone
	}
	return strings.Join(parts[:len(parts)-1], "-")
}

func renderGCPTemplate(base, project, zone, instanceName, instanceRef string) string {
	if strings.TrimSpace(base) == "" {
		return ""
	}
	repl := strings.NewReplacer(
		"{project}", project,
		"{zone}", zone,
		"{instance_name}", instanceName,
		"{instance_id}", instanceRef,
	)
	return repl.Replace(base)
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func labelValue(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.NewReplacer("@", "-", ".", "-", "_", "-", "/", "-", " ", "-").Replace(v)
	v = slugRe.ReplaceAllString(v, "-")
	v = strings.Trim(v, "-")
	if v == "" {
		return "unknown"
	}
	if len(v) > 63 {
		v = strings.Trim(v[:63], "-")
		if v == "" {
			return "unknown"
		}
	}
	return v
}

func externalIP(instance *gcpInstance) string {
	if instance == nil {
		return ""
	}
	for _, nic := range instance.NetworkInterfaces {
		for _, ac := range nic.AccessConfigs {
			if ip := strings.TrimSpace(ac.NatIP); ip != "" {
				return ip
			}
		}
	}
	return ""
}

func workstationRemoteUser(current *userstore.Workstation) string {
	if current == nil {
		return ""
	}
	return strings.TrimSpace(current.RemoteUser)
}

func workstationRemotePass(current *userstore.Workstation) string {
	if current == nil {
		return ""
	}
	return strings.TrimSpace(current.RemotePass)
}

func instanceNameFromCurrent(current *userstore.Workstation) string {
	if current == nil {
		return ""
	}
	ref := strings.TrimSpace(current.InstanceID)
	if ref == "" {
		return ""
	}
	parts := strings.Split(ref, "/")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[len(parts)-1])
}

func randomPassword() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*"
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "B0anClaw!Pass123"
	}
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(buf)
}

// ensureFirewallRules — boan-workstation 태그 인스턴스에 RDP(3389) ingress 허용.
// 파일 전송도 RDP virtual channel(drive redirection)을 통해 같은 포트로 흐른다.
// 이미 존재하면 무시.
func (p *gcpProvisioner) ensureFirewallRules(ctx context.Context) error {
	tagItems := splitCSV(strings.TrimSpace(p.cfg.WorkstationNetworkTags))
	if len(tagItems) == 0 {
		tagItems = []string{"boan-workstation"}
	}

	rules := []struct {
		name string
		port string
	}{
		{name: "boan-workstation-allow-rdp", port: "3389"},
	}

	for _, r := range rules {
		if err := p.ensureFirewallRule(ctx, r.name, r.port, tagItems); err != nil {
			return fmt.Errorf("rule %s: %w", r.name, err)
		}
	}
	return nil
}

func (p *gcpProvisioner) ensureFirewallRule(ctx context.Context, name, port string, targetTags []string) error {
	getURL := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/global/firewalls/%s",
		url.PathEscape(p.cfg.WorkstationProjectID),
		url.PathEscape(name),
	)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, getURL, nil)
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		log.Printf("[gcp-provisioner] firewall rule %s already exists", name)
		return nil
	}
	if resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("get firewall returned %d", resp.StatusCode)
	}

	// 없음 → 생성
	payload := map[string]any{
		"name":         name,
		"direction":    "INGRESS",
		"priority":     1000,
		"sourceRanges": []string{"0.0.0.0/0"},
		"targetTags":   targetTags,
		"allowed": []map[string]any{
			{"IPProtocol": "tcp", "ports": []string{port}},
		},
	}
	raw, _ := json.Marshal(payload)
	createURL := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/global/firewalls",
		url.PathEscape(p.cfg.WorkstationProjectID),
	)
	cReq, _ := http.NewRequestWithContext(ctx, http.MethodPost, createURL, bytes.NewReader(raw))
	cReq.Header.Set("Content-Type", "application/json")
	cResp, err := p.client.Do(cReq)
	if err != nil {
		return err
	}
	defer cResp.Body.Close()
	if cResp.StatusCode < 200 || cResp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(cResp.Body, 4096))
		return fmt.Errorf("create firewall returned %d: %s", cResp.StatusCode, strings.TrimSpace(string(body)))
	}
	log.Printf("[gcp-provisioner] created firewall rule %s (port %s)", name, port)
	return nil
}

func startupScript(username, password string) string {
	// 부팅 시 사용자 계정 생성 + RDP 활성화 + Desktop\boanclaw 폴더 생성.
	// 파일 전송은 Guacamole RDP drive redirection 으로 처리.
	//
	// **중요**: golden image 에서 복원된 VM 도 정확히 동일 스크립트가 돌아야
	// login 가능. 핵심은:
	//   1) Set-LocalUser -Password 로 비밀번호 덮어쓰기 (image 에 baked-in 된
	//      admin 비번은 무력화)
	//   2) Administrators **AND** Remote Desktop Users 그룹 모두 멤버십 확인
	//      (image 에서 복원된 user 는 group membership 이 깨져있을 수 있음)
	//   3) Password policy complexity 일시 해제 (랜덤 비번이 거부되는 엣지 케이스)
	//   4) 모든 단계 결과를 C:\ProgramData\boanclaw-startup.log 에 기록 → 디버깅 가능
	return fmt.Sprintf(`
$ErrorActionPreference = "Continue"
$logPath = "C:\ProgramData\boanclaw-startup.log"
function LogStep($msg) { "$(Get-Date -Format o) $msg" | Add-Content -Path $logPath }
LogStep "=== boanclaw startup begin (user=%s) ==="

# ── 계정 생성 / 비밀번호 설정 ─────────────────────────────────────────
$securePassword = ConvertTo-SecureString "%s" -AsPlainText -Force
try {
  if (-not (Get-LocalUser -Name "%s" -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name "%s" -Password $securePassword -PasswordNeverExpires -AccountNeverExpires
    LogStep "created user %s"
  } else {
    Set-LocalUser -Name "%s" -Password $securePassword -PasswordNeverExpires $true
    LogStep "reset password for existing user %s"
  }
  Enable-LocalUser -Name "%s" -ErrorAction SilentlyContinue
} catch {
  LogStep "user/pass error: $_"
}

# ── 그룹 멤버십 — Administrators + Remote Desktop Users 둘 다 확인 ──────
foreach ($grp in @("Administrators","Remote Desktop Users")) {
  try {
    Add-LocalGroupMember -Group $grp -Member "%s" -ErrorAction SilentlyContinue
    LogStep "membership ok: $grp"
  } catch { LogStep "membership fail ${grp}: $_" }
}

# ── RDP 활성화 ────────────────────────────────────────────────────────
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
# NLA 끄기 (Guacamole 와의 호환성 — RDP 2FA 스타일 검사 disable)
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -ErrorAction SilentlyContinue
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
LogStep "RDP enabled + NLA disabled"

# ── 사용자 Desktop\boanclaw 폴더 생성 ─────────────────────────────────
$userProfile = "C:\Users\%s"
$desktopBoanclaw = Join-Path $userProfile "Desktop\boanclaw"
if (-not (Test-Path $desktopBoanclaw)) {
  New-Item -ItemType Directory -Path $desktopBoanclaw -Force | Out-Null
  LogStep "created boanclaw work folder"
}
icacls $desktopBoanclaw /grant "%s:(OI)(CI)F" /T 2>&1 | Out-Null
LogStep "=== boanclaw startup end ==="
`, username, password, username, username, username, username, username, username, username, username, username)
}

// ═══════════════════════════════════════════════════════════════════════
//                            Kill Chain ops
// ═══════════════════════════════════════════════════════════════════════

// quarantineTag — kill chain 발동 시 VM 에 추가되는 network tag.
// 별도로 `boan-quarantine-deny-all` 이라는 firewall rule (Direction=EGRESS,
// priority=100, targetTags=[quarantineTag], denied=["all"]) 이 프로젝트에 있어야
// 실제로 egress 가 차단된다. terraform / gcloud 로 사전 생성 필요.
const quarantineTag = "boan-quarantine"

// IsolateNetwork — 현재 VM 의 tag 목록에 quarantineTag 추가.
// GCP 는 setTags 요청이 tags 전체를 교체하므로 기존 tags 에 추가 후 PUT.
func (p *gcpProvisioner) IsolateNetwork(ctx context.Context, current *userstore.Workstation) error {
	name := instanceNameFromCurrent(current)
	if name == "" {
		return fmt.Errorf("current workstation has no instance")
	}
	inst, err := p.getInstance(ctx, name)
	if err != nil {
		return fmt.Errorf("get instance: %w", err)
	}
	existing := map[string]struct{}{}
	for _, t := range inst.Tags.Items {
		existing[t] = struct{}{}
	}
	if _, has := existing[quarantineTag]; has {
		return nil // 이미 격리됨 — idempotent
	}
	existing[quarantineTag] = struct{}{}
	items := make([]string, 0, len(existing))
	for t := range existing {
		items = append(items, t)
	}
	payload := map[string]any{
		"items":       items,
		"fingerprint": inst.Tags.Fingerprint,
	}
	raw, _ := json.Marshal(payload)
	u := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s/setTags",
		url.PathEscape(p.cfg.WorkstationProjectID),
		url.PathEscape(p.cfg.WorkstationZone),
		url.PathEscape(name),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("setTags returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	// Best-effort: 격리 전용 firewall rule 이 있는지 확인 + 없으면 생성.
	// 없어도 오류는 내지 않고 경고만 찍음 — tag 만 붙어도 수동 점검 가능.
	if ferr := p.ensureQuarantineFirewall(ctx); ferr != nil {
		log.Printf("[killchain] quarantine firewall rule ensure failed: %v", ferr)
	}
	return nil
}

// ensureQuarantineFirewall — boan-quarantine-deny-all 규칙이 없으면 생성.
// Direction=EGRESS, priority=100 (application 의 기본 allow 보다 낮은 숫자=우선),
// targetTags=[boan-quarantine], denied=["all"].
func (p *gcpProvisioner) ensureQuarantineFirewall(ctx context.Context) error {
	rule := "boan-quarantine-deny-all"
	u := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/global/firewalls/%s",
		url.PathEscape(p.cfg.WorkstationProjectID),
		url.PathEscape(rule),
	)
	getReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	resp, err := p.client.Do(getReq)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil // already present
		}
	}
	createURL := fmt.Sprintf(
		"https://compute.googleapis.com/compute/v1/projects/%s/global/firewalls",
		url.PathEscape(p.cfg.WorkstationProjectID),
	)
	payload := map[string]any{
		"name":              rule,
		"description":       "Kill chain egress block for VMs tagged boan-quarantine",
		"direction":         "EGRESS",
		"priority":          100,
		"targetTags":        []string{quarantineTag},
		"destinationRanges": []string{"0.0.0.0/0"},
		"denied":            []map[string]any{{"IPProtocol": "all"}},
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, createURL, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	cresp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer cresp.Body.Close()
	if cresp.StatusCode < 200 || cresp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(cresp.Body, 2048))
		return fmt.Errorf("create firewall %s returned %d: %s", rule, cresp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// ForensicDiskSnapshot — kill chain 의 disk snapshot 단계. CaptureGoldenImage
// 와 동일 GCP API 를 쓰되 이름에 incident ID 를 끼워 넣어 식별 가능하게 함.
// CaptureGoldenImage 는 snapshot 후 VM 을 재시작하는데, kill chain 에서는
// 다음 단계가 STOP/DELETE 이므로 restart 는 의미 없다. 그래도 재사용 OK —
// STOP 은 멱등하고 다음 StopInstance 가 다시 확실히 stop.
func (p *gcpProvisioner) ForensicDiskSnapshot(ctx context.Context, current *userstore.Workstation, incidentID string) (string, error) {
	name := instanceNameFromCurrent(current)
	if name == "" {
		return "", fmt.Errorf("current workstation has no instance")
	}
	// 이름 규칙: boan-forensic-{instance}-{incident}-{unix}
	// 최대 63자 + lowercase + dash 제약 맞추기.
	sanitize := func(s string) string {
		out := make([]byte, 0, len(s))
		for i := 0; i < len(s); i++ {
			c := s[i]
			if c >= 'A' && c <= 'Z' {
				c += 32
			}
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
				out = append(out, c)
			} else {
				out = append(out, '-')
			}
		}
		return string(out)
	}
	incShort := sanitize(incidentID)
	if len(incShort) > 20 {
		incShort = incShort[len(incShort)-20:]
	}
	imageName := fmt.Sprintf("boan-forensic-%s-%s-%d", sanitize(name), incShort, time.Now().Unix())
	if len(imageName) > 63 {
		imageName = imageName[:63]
	}
	return p.CaptureGoldenImage(ctx, current, imageName, fmt.Sprintf("forensic snapshot for incident %s", incidentID))
}

// StopInstance — gcpProvisioner 의 내부 stopInstance 래퍼.
func (p *gcpProvisioner) StopInstance(ctx context.Context, current *userstore.Workstation) error {
	name := instanceNameFromCurrent(current)
	if name == "" {
		return fmt.Errorf("current workstation has no instance")
	}
	return p.stopInstance(ctx, name)
}
