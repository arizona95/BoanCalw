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

type gcpProvisioner struct {
	cfg            *config.Config
	client         *http.Client
	firewallOnce   sync.Once
}

type gcpInstance struct {
	ID                any               `json:"id"`
	Name              string            `json:"name"`
	Status            string            `json:"status"`
	Labels            map[string]string `json:"labels"`
	Zone              string            `json:"zone"`
	Metadata          gcpMetadata       `json:"metadata"`
	NetworkInterfaces []gcpNIC          `json:"networkInterfaces"`
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
		"disks": []disk{
			{
				Boot:       true,
				AutoDelete: true,
				InitializeParams: diskInit{
					SourceImage: fmt.Sprintf("projects/%s/global/images/family/%s", p.cfg.WorkstationImageProject, p.cfg.WorkstationImageFamily),
					DiskSizeGb:  fmt.Sprintf("%d", p.cfg.WorkstationRootVolumeGiB),
					DiskType:    fmt.Sprintf("zones/%s/diskTypes/pd-balanced", zone),
				},
			},
		},
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
	// 파일 전송은 Guacamole RDP drive redirection (3389/RDP virtual channel) 으로 처리하므로
	// OpenSSH/SCP 설치가 필요 없다.
	return fmt.Sprintf(`
$ErrorActionPreference = "Stop"

# ── 계정 생성 / 비밀번호 설정 ─────────────────────────────────────────
$securePassword = ConvertTo-SecureString "%s" -AsPlainText -Force
if (-not (Get-LocalUser -Name "%s" -ErrorAction SilentlyContinue)) {
  New-LocalUser -Name "%s" -Password $securePassword -PasswordNeverExpires -AccountNeverExpires
} else {
  Set-LocalUser -Name "%s" -Password $securePassword
}
Add-LocalGroupMember -Group "Administrators" -Member "%s" -ErrorAction SilentlyContinue

# ── RDP 활성화 ────────────────────────────────────────────────────────
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# ── 사용자 Desktop\boanclaw 폴더 생성 (사용자가 RDP 안에서 BoanClaw 드라이브와 파일을 주고받는 작업 폴더) ─────────────
$userProfile = "C:\Users\%s"
$desktopBoanclaw = Join-Path $userProfile "Desktop\boanclaw"
if (-not (Test-Path $desktopBoanclaw)) {
  New-Item -ItemType Directory -Path $desktopBoanclaw -Force | Out-Null
}
icacls $desktopBoanclaw /grant "%s:(OI)(CI)F" /T 2>&1 | Out-Null
`, password, username, username, username, username, username, username)
}
