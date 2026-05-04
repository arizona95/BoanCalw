package threatleader

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// SelectTopProposals — Advisory 들에서 top N Proposal 선별.
//   * severity HIGH/CRITICAL 우선 (또는 CVSS ≥ 7).
//   * skipState 의 seen / ignored 에 있는 ID 는 제외.
//   * published_at desc 후 severity desc 로 정렬.
func SelectTopProposals(advs []Advisory, limit int, skip *State) []Proposal {
	out := make([]Proposal, 0, len(advs))
	for _, a := range advs {
		p := toProposal(a)
		if p.PackageName == "" {
			continue
		}
		if skip != nil {
			if skip.Seen[p.ID] || skip.Ignored[p.ID] {
				continue
			}
		}
		// 너무 심각도 낮은 건 제외 — top 5 의미 있게.
		if p.Severity == "low" {
			continue
		}
		out = append(out, p)
	}
	// 정렬: critical > high > medium, 같은 severity 내에선 published 최신.
	sevRank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "": 0}
	sort.SliceStable(out, func(i, j int) bool {
		if sevRank[out[i].Severity] != sevRank[out[j].Severity] {
			return sevRank[out[i].Severity] > sevRank[out[j].Severity]
		}
		return out[i].PublishedAt.After(out[j].PublishedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func toProposal(a Advisory) Proposal {
	p := Proposal{
		ID:          a.ID,
		Summary:     truncate(a.Summary, 200),
		Description: truncate(a.Details, 1200),
		PublishedAt: parseTime(a.Published),
		ModifiedAt:  parseTime(a.Modified),
	}
	for _, alias := range a.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			p.CVEID = alias
			break
		}
	}
	if len(a.Affected) > 0 {
		ap := a.Affected[0]
		p.Ecosystem = ap.Package.Ecosystem
		p.PackageName = ap.Package.Name
		p.VersionsAffected = formatRanges(ap.Ranges)
		p.SuggestedProcess = ecosystemProcess(ap.Package.Ecosystem)
	}
	if len(a.References) > 0 {
		// advisory / web reference 우선.
		for _, r := range a.References {
			if r.Type == "ADVISORY" || r.Type == "WEB" {
				p.ReferenceURL = r.URL
				break
			}
		}
		if p.ReferenceURL == "" {
			p.ReferenceURL = a.References[0].URL
		}
	}
	p.Severity, p.CVSSScore = cvssLevel(a.Severity)
	if p.SuggestedRuleName == "" {
		p.SuggestedRuleName = fmt.Sprintf("Threat Leader: %s @ %s%s", p.PackageName, p.Ecosystem, severitySuffix(p.Severity))
	}
	return p
}

// ecosystemProcess — 에코시스템별 의심 process_name 추정.
// (정확한 매칭은 phase v3 에서 LLM 분석; 현재는 런타임 명만으로 충분.)
func ecosystemProcess(eco string) string {
	switch strings.ToLower(eco) {
	case "npm":
		return "node"
	case "pypi":
		return "python"
	case "go":
		return "go"
	case "rubygems":
		return "ruby"
	case "maven":
		return "java"
	case "packagist":
		return "php"
	default:
		return ""
	}
}

// CVSS score 정규식 — "CVSS:3.1/AV:N/.../A:H" 의 베이스 score 가 별도 필드면
// 따로 보지만 OSV 의 score 는 보통 vector string. 여기선 vector → 단순 mapping
// (severity 라벨 우선) 으로 결정. database_specific.severity 가 있으면 그것 우선.
var cvssScoreRe = regexp.MustCompile(`(?i)\bCVSS:[\d.]+/[A-Z:/.]+\b`)

func cvssLevel(items []SeverityItem) (string, float64) {
	for _, it := range items {
		score := strings.TrimSpace(it.Score)
		// Score 가 그냥 숫자 (e.g., "9.8") 인 경우 우선.
		if v := parseFloat(score); v > 0 {
			return scoreToLabel(v), v
		}
		// Vector string 에서 base score 직접 계산은 무거움 — 휴리스틱:
		// vector 안 "AV:N" + "AC:L" + "C:H" 등 가산.
		if cvssScoreRe.MatchString(score) {
			return heuristicSeverity(score), 0
		}
	}
	return "medium", 0
}

func scoreToLabel(v float64) string {
	switch {
	case v >= 9.0:
		return "critical"
	case v >= 7.0:
		return "high"
	case v >= 4.0:
		return "medium"
	default:
		return "low"
	}
}

// heuristicSeverity — CVSS vector 의 impact metric 만으로 대략 severity.
// CVSS:* 의 C:H/I:H/A:H 가 보이면 high+, 다 N 이면 low.
func heuristicSeverity(s string) string {
	upper := strings.ToUpper(s)
	score := 0
	if strings.Contains(upper, "AV:N") {
		score += 2
	}
	if strings.Contains(upper, "AC:L") {
		score += 1
	}
	if strings.Contains(upper, "C:H") || strings.Contains(upper, "I:H") || strings.Contains(upper, "A:H") {
		score += 5
	}
	if strings.Contains(upper, "PR:N") {
		score += 1
	}
	if strings.Contains(upper, "UI:N") {
		score += 1
	}
	switch {
	case score >= 9:
		return "critical"
	case score >= 6:
		return "high"
	case score >= 3:
		return "medium"
	default:
		return "low"
	}
}

func severitySuffix(s string) string {
	if s == "critical" {
		return " (CRITICAL)"
	}
	return ""
}

func formatRanges(rs []VersionRange) string {
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		var introduced, fixed string
		for _, e := range r.Events {
			if e.Introduced != "" && e.Introduced != "0" {
				introduced = e.Introduced
			}
			if e.Fixed != "" {
				fixed = e.Fixed
			}
		}
		switch {
		case introduced != "" && fixed != "":
			parts = append(parts, fmt.Sprintf(">=%s,<%s", introduced, fixed))
		case fixed != "":
			parts = append(parts, fmt.Sprintf("<%s", fixed))
		case introduced != "":
			parts = append(parts, fmt.Sprintf(">=%s", introduced))
		}
	}
	if len(parts) == 0 {
		return "all versions"
	}
	return strings.Join(parts, "; ")
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func parseFloat(s string) float64 {
	var v float64
	_, _ = fmt.Sscanf(s, "%f", &v)
	return v
}
