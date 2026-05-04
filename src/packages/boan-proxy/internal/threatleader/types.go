// Package threatleader — OSV.dev 공급망 공격 정보를 fetch 해서 Kill Chain rule
// 후보로 추천하는 HITL 흐름.
//
// 흐름:
//   1) Refresher goroutine 이 24h 주기 (또는 즉시 트리거) 로 OSV bucket 데일리
//      dump 다운 + 최근 7일 + severity HIGH/CRITICAL top 5 선별.
//   2) UI (Threat Leader 페이지) 가 GET /api/threat-leader/proposals 로 5 개 노출.
//   3) admin 이 Accept → KillChain rule 추가 (auto=true) — 이후 사용자 컴퓨터에서
//      해당 process 보면 즉시 격리 → 포렌식 스냅샷 → STOP → DELETE.
//      Reject → ignored 마킹 (다음 라운드에 다시 추천 안 함).
//
// 데이터 소스: https://storage.googleapis.com/osv-vulnerabilities/{ecosystem}/all.zip
// (OSV.dev 가 자동 데일리 export 하는 GCS bucket. 무인증, 무한 호출.)

package threatleader

import "time"

// Advisory — OSV 표준 JSON 의 핵심 필드만 파싱 (전체 schema 는 더 큼).
// https://ossf.github.io/osv-schema/
type Advisory struct {
	ID         string         `json:"id"`         // OSV ID, 예: "GHSA-xxxx-yyyy-zzzz"
	Modified   string         `json:"modified"`   // RFC3339
	Published  string         `json:"published"`  // RFC3339
	Aliases    []string       `json:"aliases"`    // CVE-XXXX-YYYY 등
	Summary    string         `json:"summary"`
	Details    string         `json:"details"`
	Affected   []AffectedPkg  `json:"affected"`
	Severity   []SeverityItem `json:"severity"`
	References []Reference    `json:"references"`
}

type AffectedPkg struct {
	Package PackageRef    `json:"package"`
	Ranges  []VersionRange `json:"ranges"`
}

type PackageRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Purl      string `json:"purl"`
}

type VersionRange struct {
	Type   string         `json:"type"`
	Events []VersionEvent `json:"events"`
}

type VersionEvent struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type SeverityItem struct {
	Type  string `json:"type"`  // "CVSS_V3" 등
	Score string `json:"score"` // "CVSS:3.1/AV:N/..." 등
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Proposal — UI 가 표시하는 5 개 후보. Advisory 에서 가공.
type Proposal struct {
	ID                  string    `json:"id"`                    // Advisory.ID
	CVEID               string    `json:"cve_id,omitempty"`      // Aliases 중 CVE-* 첫번째
	Ecosystem           string    `json:"ecosystem"`             // npm | PyPI | Go | ...
	PackageName         string    `json:"package_name"`
	VersionsAffected    string    `json:"versions_affected"`     // "<1.7.4" 등 정리된 form
	Summary             string    `json:"summary"`
	Description         string    `json:"description"`
	PublishedAt         time.Time `json:"published_at"`
	ModifiedAt          time.Time `json:"modified_at"`
	Severity            string    `json:"severity"`              // "low|medium|high|critical"
	CVSSScore           float64   `json:"cvss_score,omitempty"`  // 숫자 비교용
	SuggestedProcess    string    `json:"suggested_process"`     // "node" | "python" | ...
	SuggestedRuleName   string    `json:"suggested_rule_name"`
	ReferenceURL        string    `json:"reference_url,omitempty"`
}

// State — store 에 보존하는 사용자 결정.
// seen: Accept 한 advisory ID set (= 이미 KillChain rule 등록됨).
// ignored: Reject 한 advisory ID set (= 다음 라운드 추천 후보에서 제외).
type State struct {
	Seen        map[string]bool `json:"seen"`
	Ignored     map[string]bool `json:"ignored"`
	LastFetchAt time.Time       `json:"last_fetch_at"`
	Latest      []Proposal      `json:"latest"`
}
