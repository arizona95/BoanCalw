package credential

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Status string

const (
	StatusOK             Status = "ok"
	StatusExpired        Status = "expired"
	StatusMissing        Status = "missing_credential"
	StatusInvalidExpires Status = "invalid_expires"
	StatusUnresolved     Status = "unresolved_ref"
)

type Credential struct {
	Name      string    `json:"name"`
	Value     string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
	Status    Status    `json:"status"`
	Header    string    `json:"header"`
	Ref       string    `json:"ref"`
}

type Manager struct {
	mu          sync.RWMutex
	creds       map[string]*Credential
	filterURL   string
	orgID       string
	client      *http.Client
	refreshBuf  time.Duration
}

func NewManager(filterURL, orgID string) *Manager {
	return &Manager{
		creds:      make(map[string]*Credential),
		filterURL:  filterURL,
		orgID:      orgID,
		client:     &http.Client{Timeout: 10 * time.Second},
		refreshBuf: 30 * time.Second,
	}
}

func Resolve(ctx context.Context, filterURL, orgID, role string) (string, error) {
	role = strings.TrimSpace(role)
	if role == "" {
		return "", fmt.Errorf("empty credential role")
	}
	candidates := []string{role}
	if !strings.HasSuffix(role, "-apikey") {
		candidates = append(candidates, role+"-apikey")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, candidate := range candidates {
		endpoint := fmt.Sprintf("%s/credential/%s/%s", strings.TrimRight(filterURL, "/"), orgID, url.PathEscape(candidate))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return "", err
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		var data struct {
			Key    string `json:"key"`
			Status string `json:"status"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&data)
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode < 300 && data.Status == "ok" && data.Key != "" {
			return data.Key, nil
		}
	}
	return "", fmt.Errorf("credential %q not found", role)
}

func (m *Manager) Get(name string) (string, error) {
	m.mu.RLock()
	c, ok := m.creds[name]
	m.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("%s: %s", name, StatusMissing)
	}

	if c.Ref != "" && c.Value == "" {
		return "", fmt.Errorf("%s: %s", name, StatusUnresolved)
	}

	if c.ExpiresAt.IsZero() && c.Status == StatusOK {
		return "", fmt.Errorf("%s: %s", name, StatusInvalidExpires)
	}

	if c.Status != StatusOK {
		return "", fmt.Errorf("%s: %s", name, c.Status)
	}

	if time.Now().After(c.ExpiresAt) {
		if err := m.renew(context.Background(), name); err != nil {
			m.mu.Lock()
			c.Status = StatusExpired
			m.mu.Unlock()
			return "", fmt.Errorf("%s: %s", name, StatusExpired)
		}
		m.mu.RLock()
		defer m.mu.RUnlock()
		return m.creds[name].Value, nil
	}

	if time.Until(c.ExpiresAt) < m.refreshBuf {
		go func() {
			_ = m.renew(context.Background(), name)
		}()
	}

	return c.Value, nil
}

func (m *Manager) InjectHeader(r *http.Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, c := range m.creds {
		if c.Status != StatusOK || time.Now().After(c.ExpiresAt) {
			continue
		}
		header := c.Header
		if header == "" {
			switch c.Name {
			case "api_key":
				header = "X-API-Key"
			default:
				header = "Authorization"
			}
		}
		switch header {
		case "Authorization":
			r.Header.Set(header, "Bearer "+c.Value)
		default:
			r.Header.Set(header, c.Value)
		}
	}
}

func (m *Manager) CredentialCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.creds)
}

func (m *Manager) StatusSummary() map[string]Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]Status, len(m.creds))
	for k, c := range m.creds {
		if time.Now().After(c.ExpiresAt) && c.Status == StatusOK {
			out[k] = StatusExpired
		} else {
			out[k] = c.Status
		}
	}
	return out
}

func (m *Manager) StartRefresh(ctx context.Context, interval time.Duration) {
	go func() {
		m.fetchAll()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.fetchAll()
			}
		}
	}()
}

func (m *Manager) fetchAll() {
	if m.filterURL == "" {
		return
	}
	url := fmt.Sprintf("%s/org/%s/credentials", m.filterURL, m.orgID)
	resp, err := m.client.Get(url)
	if err != nil {
		log.Printf("credential: fetch failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("credential: fetch returned status %d", resp.StatusCode)
		return
	}

	var creds []*Credential
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		log.Printf("credential: decode failed: %v", err)
		return
	}
	m.mu.Lock()
	for _, c := range creds {
		c.Status = m.validateCredential(c)
		m.creds[c.Name] = c
	}
	m.mu.Unlock()
}

func (m *Manager) validateCredential(c *Credential) Status {
	if c.Ref != "" && c.Value == "" {
		return StatusUnresolved
	}
	if c.ExpiresAt.IsZero() {
		return StatusInvalidExpires
	}
	if time.Now().After(c.ExpiresAt) {
		return StatusExpired
	}
	return StatusOK
}

func (m *Manager) renew(ctx context.Context, name string) error {
	if m.filterURL == "" {
		return fmt.Errorf("no filter URL configured")
	}
	url := fmt.Sprintf("%s/org/%s/credentials/%s/renew", m.filterURL, m.orgID, name)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("renew returned status %d", resp.StatusCode)
	}

	var c Credential
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return err
	}
	c.Status = m.validateCredential(&c)
	m.mu.Lock()
	m.creds[name] = &c
	m.mu.Unlock()
	return nil
}
