package threatleader

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Ecosystems — fetch 대상 (OSV bucket 의 디렉토리 이름과 동일).
// npm + PyPI 우선. 추후 Go / Maven / RubyGems 등 추가.
var Ecosystems = []string{"npm", "PyPI"}

const osvBucketBase = "https://storage.googleapis.com/osv-vulnerabilities"

// directHTTPClient — boan-proxy 의 HTTP_PROXY 환경변수를 무시하고 직접 outbound.
// sandbox 컨테이너 안에서 boan-proxy 가 동작할 때 자기 자신의 listener (HTTPS_PROXY=
// localhost:18080) 를 통과시키면 storage.googleapis.com 이 whitelist 에 없어서 차단됨.
// threat-leader 의 OSV fetch 는 내부 작업이라 outbound gate 없이 직접 가야 자연스러움.
var directHTTPClient = &http.Client{
	Timeout: 120 * time.Second,
	Transport: &http.Transport{
		Proxy:               nil, // 환경변수 무시.
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	},
}

// FetchEcosystem — OSV bucket 의 데일리 zip 다운 + JSON parse.
// 사이즈가 큼 (~10-50MB compressed) — 매일 1번만 호출하는 흐름이라 OK.
// Returns advisories modified within the last `lookback` window.
func FetchEcosystem(ctx context.Context, ecosystem string, lookback time.Duration) ([]Advisory, error) {
	url := fmt.Sprintf("%s/%s/all.zip", osvBucketBase, ecosystem)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := directHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv fetch %s: %w", ecosystem, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv fetch %s: status %d", ecosystem, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("osv read %s: %w", ecosystem, err)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("osv zip %s: %w", ecosystem, err)
	}
	cutoff := time.Now().Add(-lookback)
	out := make([]Advisory, 0, 256)
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, oerr := f.Open()
		if oerr != nil {
			continue
		}
		var a Advisory
		jerr := json.NewDecoder(rc).Decode(&a)
		rc.Close()
		if jerr != nil {
			continue
		}
		t := parseTime(a.Modified)
		if t.IsZero() || t.Before(cutoff) {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// 일부 advisory 가 fractional 또는 변형 — RFC3339Nano fallback.
		t, err = time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return time.Time{}
		}
	}
	return t
}
