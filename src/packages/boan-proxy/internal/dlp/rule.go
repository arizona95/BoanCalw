package dlp

import (
	"regexp"
	"strings"
	"sync"
)

type SLevel int

const (
	SLevelUnknown SLevel = 0
	SLevel1       SLevel = 1
	SLevel2       SLevel = 2
	SLevel3       SLevel = 3
	SLevel4       SLevel = 4
)

func (l SLevel) String() string {
	switch l {
	case SLevel1:
		return "S1"
	case SLevel2:
		return "S2"
	case SLevel3:
		return "S3"
	case SLevel4:
		return "S4"
	default:
		return "S0"
	}
}

type Finding struct {
	RuleName string
	Level    SLevel
	Match    string
}

type rulePattern struct {
	name  string
	level SLevel
	re    *regexp.Regexp
}

var (
	compiledOnce sync.Once
	patterns     []rulePattern
)

func initPatterns() {
	compiledOnce.Do(func() {
		patterns = []rulePattern{
			{"aws_key", SLevel4, regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`)},
			{"aws_secret", SLevel4, regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}`)},
			{"pem_key", SLevel4, regexp.MustCompile(`-----BEGIN (RSA |EC )?PRIVATE KEY-----`)},
			{"db_url", SLevel4, regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis)://[^@\s]+:[^@\s]+@`)},
			{"jwt_token", SLevel3, regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`)},
			{"kr_rrn", SLevel3, regexp.MustCompile(`\b\d{6}[-]\d{7}\b`)},
			{"kr_phone", SLevel3, regexp.MustCompile(`\b01[0-9][-]?\d{3,4}[-]?\d{4}\b`)},
			{"generic_secret", SLevel3, regexp.MustCompile(`(?i)(secret|password|passwd|api.?key)\s*[:=]\s*['\"]?[^\s'"]{8,}`)},
			{"api_key_generic", SLevel3, regexp.MustCompile(`(?i)(sk|pk)[-_](?:live|test)[-_][a-zA-Z0-9]{20,}`)},
			{"ip_internal", SLevel2, regexp.MustCompile(`\b(10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)\b`)},
			{"email_addr", SLevel2, regexp.MustCompile(`\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`)},
		}
	})
}

func Scan(text string) []Finding {
	initPatterns()
	var findings []Finding
	for _, p := range patterns {
		matches := p.re.FindAllString(text, -1)
		for _, m := range matches {
			findings = append(findings, Finding{
				RuleName: p.name,
				Level:    p.level,
				Match:    m,
			})
		}
	}
	return findings
}

func MaxLevel(findings []Finding) SLevel {
	level := SLevel1
	for _, f := range findings {
		if f.Level > level {
			level = f.Level
		}
	}
	return level
}

func MatchedNames(findings []Finding) []string {
	seen := make(map[string]bool)
	var names []string
	for _, f := range findings {
		if !seen[f.RuleName] {
			seen[f.RuleName] = true
			names = append(names, f.RuleName)
		}
	}
	return names
}

func RulesLoaded() int {
	initPatterns()
	return len(patterns)
}

func Redact(text string) string {
	initPatterns()
	for _, p := range patterns {
		if p.level <= SLevel2 {
			continue
		}
		text = p.re.ReplaceAllStringFunc(text, func(_ string) string {
			return "[REDACTED:" + strings.ToUpper(p.name) + "]"
		})
	}
	return text
}
