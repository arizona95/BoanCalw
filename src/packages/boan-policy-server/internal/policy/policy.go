package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type NetworkEndpoint struct {
	Host    string   `json:"host"`
	Ports   []int    `json:"ports,omitempty"`
	Methods []string `json:"methods,omitempty"`
	// System — true 이면 deploy 시 주입된 필수 endpoint (정책서버/LLM proxy
	// 등). 관리자도 UI 에서 지울 수 없고 updatePolicy 는 incoming 에서 자동
	// 제거. 매 read 마다 다시 prepend 되어 사라지지 않는다. 이게 없으면
	// 정책 변경 후 자기 자신이 정책을 못 가져오는 recursive deadlock 발생.
	System bool `json:"system,omitempty"`
}

type DLPRule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	SLevel  int    `json:"slevel"`
}

type RBACRole struct {
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	SLevel      int      `json:"slevel"`
}

type RBACConfig struct {
	Roles         []RBACRole `json:"roles"`
	DefaultRole   string     `json:"default_role"`
	EnforceStrict bool       `json:"enforce_strict"`
}

type VersionPolicy struct {
	MinVersion      string   `json:"min_version,omitempty"`
	BlockedVersions []string `json:"blocked_versions,omitempty"`
	UpdateChannel   string   `json:"update_channel,omitempty"`
}

type SSOProvider struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Enabled     bool   `json:"enabled"`
	Configured  bool   `json:"configured"`
	RedirectURI string `json:"redirect_uri,omitempty"`
}

type OrgSettings struct {
	OrgName        string        `json:"org_name,omitempty"`
	AllowedSSO     []SSOProvider `json:"allowed_sso,omitempty"`
	AllowedDomains []string      `json:"allowed_domains,omitempty"` // SSO 허용 이메일 도메인
	AdminEmails    []string      `json:"admin_emails,omitempty"`
	SeatLimit      int           `json:"seat_limit,omitempty"`
	GCPOrgID       string        `json:"gcp_org_id,omitempty"`
	WorkspaceURL   string        `json:"workspace_url,omitempty"`
	MountRoot      string        `json:"mount_root,omitempty"`
	// MountRules: 정규식 기반 파일/폴더 접근 제한 규칙.
	// 기본값은 전체 read+write 허용. 규칙은 매칭되는 경로의 권한을 "낮추는"
	// 방향으로만 동작 (read_only → 쓰기 차단, ask → 승인 필요, deny → 차단).
	// 위→아래 순서로 첫 매칭이 적용됨.
	MountRules []MountRule `json:"mount_rules,omitempty"`
}

// MountRule — 마운트 경로 하위의 파일/폴더에 대한 접근 제한 규칙
//   - Pattern: 정규식 (mount_root 하위 상대경로 기준)
//   - Mode:
//       "deny" — 읽기만 가능, write 차단
//       "ask"  — 접근 시 사용자 본인에게 HITL 확인 팝업 (소유자 승인 큐가 아님)
type MountRule struct {
	Pattern string `json:"pattern"`
	Mode    string `json:"mode"`
}

// NormalizeMountMode coerces a free-form value into one of deny|ask.
// 빈 값 / 알 수 없는 값 → "deny" (가장 약한 제한 = 읽기만 허용).
// 호환을 위해 "read_only" / "readonly" 도 "deny" 로 매핑한다.
func NormalizeMountMode(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "deny", "read_only", "readonly":
		return "deny"
	case "ask":
		return "ask"
	default:
		return "deny"
	}
}

type GuardrailConfig struct {
	// GT1 — 텍스트 정규식 가드레일 (기본 패턴은 input_gate.go 에 하드코딩되어 있으며,
	// 여기 GT1Patterns 는 조직별로 추가되는 사용자 정의 패턴 + 설명)
	// JSON 태그는 레거시 호환을 위해 g1_custom_patterns 유지.
	GT1Patterns []GT1Pattern `json:"g1_custom_patterns,omitempty"`

	// GT2 — 헌법 + LLM 텍스트 가드레일. 이 텍스트가 GT2 LLM 시스템 프롬프트로 사용됨.
	GT2Constitution string `json:"constitution,omitempty"`

	// GT3 — Wiki 적응형 텍스트 가드레일. 운영자가 제공하는 추가 힌트/맥락
	// (예: "사내 code review 텍스트는 외부 전송 금지" 등의 자연어 메모)
	GT3WikiHint string `json:"g3_wiki_hint,omitempty"`

	// GI1 — 이미지 perceptual-hash 차단 리스트. 들어오는 이미지 pHash 와
	// Hamming distance < GI1HammingThreshold 이면 차단/치환.
	GI1Forbidden        []GI1ForbiddenImage `json:"gi1_forbidden,omitempty"`
	GI1HammingThreshold int                 `json:"gi1_hamming_threshold,omitempty"` // 기본 10

	// GI2 — Vision-LLM 이미지 설명 매칭. description 에 매칭되면 ask → HITL.
	GI2Descriptions []GI2Description `json:"gi2_descriptions,omitempty"`

	// (레거시 — 현재 사용 안 함) 가드레일 LLM endpoint/model 커스터마이즈.
	// LLM Registry 역할 바인딩으로 대체됨.
	LLMURL       string `json:"llm_url,omitempty"`
	LLMModel     string `json:"llm_model,omitempty"`
	WikiLLMURL   string `json:"wiki_llm_url,omitempty"`
	WikiLLMModel string `json:"wiki_llm_model,omitempty"`
}

// GT1Pattern — 조직 텍스트 정규식 + 설명 + 매칭 시 동작
// Mode:
//   "credential" — 매칭된 값이 credential 이라 간주. credential 치환 로직 경유 (기본 5 패턴 mode)
//   "redact"     — 캡쳐된 부분을 Replacement 로 치환해서 통과
//   "block"      — 캡쳐된 부분을 sentinel 로 치환 (Replacement 비어있으면 [guardrail::GT1::block])
type GT1Pattern struct {
	Pattern     string `json:"pattern"`
	Description string `json:"description,omitempty"`
	// Replacement: 매칭된 텍스트를 이 값으로 치환해서 downstream 에 전달.
	// 예: "{{GT1::phone_number}}" → 원문의 폰번호 자리에 플레이스홀더가 들어가고 가드레일은 통과.
	Replacement string `json:"replacement,omitempty"`
	Mode        string `json:"mode,omitempty"` // "redact" | "block" | "credential"
}

// GI1ForbiddenImage — 차단할 이미지의 perceptual hash + 설명
// Hash 는 64-bit pHash (16자리 hex). Hamming distance 기준 비교.
type GI1ForbiddenImage struct {
	Hash        string `json:"hash"`                  // 16-hex pHash
	Description string `json:"description,omitempty"` // 운영자가 보는 라벨 (예: "내부 회로도")
	UploadedAt  string `json:"uploaded_at,omitempty"`
	Replacement string `json:"replacement,omitempty"` // 차단 시 downstream 에 보낼 placeholder 텍스트
}

// GI2Description — 차단되어야 할 이미지의 자연어 설명. Vision-LLM 이 이걸 보고
// 들어온 이미지가 이 설명에 부합하면 ask → HITL.
type GI2Description struct {
	Description string `json:"description"`     // 예: "회로도, 도면, 스키매틱"
	Action      string `json:"action,omitempty"` // "ask" | "block" (기본: ask)
}

type Policy struct {
	Version       int               `json:"version"`
	OrgID         string            `json:"org_id"`
	UpdatedAt     time.Time         `json:"updated_at"`
	Network       []NetworkEndpoint `json:"network_whitelist"`
	DLPRules      []DLPRule         `json:"dlp_rules"`
	RBAC          RBACConfig        `json:"rbac"`
	VersionPolicy VersionPolicy     `json:"version_policy,omitempty"`
	OrgSettings   OrgSettings       `json:"org_settings,omitempty"`
	Guardrail     GuardrailConfig   `json:"guardrail,omitempty"`
	Signature     string            `json:"signature,omitempty"`
}

type VersionInfo struct {
	Version   int       `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

const MaxVersions = 10

// MountRootFromEnv returns BOAN_MOUNT_ROOT, falling back to $HOME/Desktop/boanclaw.
func MountRootFromEnv() string {
	if v := os.Getenv("BOAN_MOUNT_ROOT"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "/root"
	}
	return filepath.Join(home, "Desktop", "boanclaw")
}

type Store struct {
	mu  sync.RWMutex
	dir string
}

func NewStore(dir string) *Store {
	os.MkdirAll(dir, 0700)
	return &Store{dir: dir}
}

func DefaultPolicy(orgID string) *Policy {
	return &Policy{
		Version:   1,
		OrgID:     orgID,
		UpdatedAt: time.Now().UTC(),
		Network: []NetworkEndpoint{
			{Host: "api.anthropic.com", Ports: []int{443}, Methods: []string{"POST"}},
			// 내부 grounding LLM 서버 (vLLM container, OpenAI-호환). docker network 내부 DNS.
			{Host: "boan-grounding", Ports: []int{8000}, Methods: []string{"POST", "GET"}},
		},
		RBAC: RBACConfig{
			DefaultRole:   "user",
			EnforceStrict: true,
			Roles: []RBACRole{
				{Role: "owner", Permissions: []string{"policy:*", "org:*", "audit:*"}, SLevel: 4},
				{Role: "user", Permissions: []string{"workspace:use"}, SLevel: 2},
			},
		},
		VersionPolicy: VersionPolicy{
			MinVersion:      "0.1.0",
			BlockedVersions: []string{},
			UpdateChannel:   "stable",
		},
		OrgSettings: OrgSettings{
			OrgName: orgID,
			AllowedSSO: []SSOProvider{
				{ID: "email_otp", Label: "Company Email OTP", Enabled: true, Configured: true},
			},
			MountRoot: MountRootFromEnv(),
		},
		Guardrail: GuardrailConfig{
			GT2Constitution: "가드레일 헌법: 자격증명, 비밀번호, 토큰, 개인정보, 사내 비밀, 고객 데이터, 민감한 운영 명령은 외부로 그대로 내보내지 않는다. 완전 무해한 일반 텍스트만 허용한다. 애매하면 ask 로 분류하고 사람 확인을 거친다.",
		},
	}
}

func (s *Store) orgDir(orgID string) string {
	d := filepath.Join(s.dir, orgID)
	os.MkdirAll(d, 0700)
	return d
}

func (s *Store) Save(p *Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p.UpdatedAt = time.Now().UTC()
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(s.orgDir(p.OrgID), fmt.Sprintf("v%d.json", p.Version))
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return err
	}
	s.pruneVersions(p.OrgID)
	return nil
}

func (s *Store) Load(orgID string) (*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions := s.scanVersions(orgID)
	if len(versions) == 0 {
		return nil, fmt.Errorf("no policy for org %s", orgID)
	}
	return s.loadFile(s.orgDir(orgID), versions[len(versions)-1].Version)
}

func (s *Store) EnsureDefault(orgID string) (*Policy, error) {
	if p, err := s.Load(orgID); err == nil {
		return p, nil
	}
	p := DefaultPolicy(orgID)
	if err := s.Save(p); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Store) LoadVersion(orgID string, version int) (*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadFile(s.orgDir(orgID), version)
}

func (s *Store) ListVersions(orgID string) []VersionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scanVersions(orgID)
}

func (s *Store) NextVersion(orgID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions := s.scanVersions(orgID)
	if len(versions) == 0 {
		return 1
	}
	return versions[len(versions)-1].Version + 1
}

func (s *Store) scanVersions(orgID string) []VersionInfo {
	dir := s.orgDir(orgID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var versions []VersionInfo
	for _, e := range entries {
		var ver int
		if n, _ := fmt.Sscanf(e.Name(), "v%d.json", &ver); n == 1 {
			info, _ := e.Info()
			var updated time.Time
			if info != nil {
				updated = info.ModTime()
			}
			versions = append(versions, VersionInfo{Version: ver, UpdatedAt: updated})
		}
	}
	sort.Slice(versions, func(i, j int) bool {
		return versions[i].Version < versions[j].Version
	})
	return versions
}

func (s *Store) pruneVersions(orgID string) {
	versions := s.scanVersions(orgID)
	if len(versions) <= MaxVersions {
		return
	}
	dir := s.orgDir(orgID)
	for _, v := range versions[:len(versions)-MaxVersions] {
		os.Remove(filepath.Join(dir, fmt.Sprintf("v%d.json", v.Version)))
	}
}

func (s *Store) loadFile(dir string, version int) (*Policy, error) {
	path := filepath.Join(dir, fmt.Sprintf("v%d.json", version))
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	// MountRoot is sourced from env var (BOAN_MOUNT_ROOT) — always override
	// the persisted value so changes to the env var take effect immediately.
	p.OrgSettings.MountRoot = MountRootFromEnv()
	if p.Guardrail.GT2Constitution == "" {
		p.Guardrail.GT2Constitution = DefaultPolicy(p.OrgID).Guardrail.GT2Constitution
	}
	return &p, nil
}
