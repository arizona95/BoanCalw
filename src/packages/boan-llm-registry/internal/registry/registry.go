package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Scope string

const (
	ScopeInternal  Scope = "INTERNAL"
	ScopeExternal  Scope = "EXTERNAL"
	ScopeConnector Scope = "CONNECTOR"
)

type LLMObject struct {
	Name              string            `json:"name"`
	Endpoint          string            `json:"endpoint"`
	Scope             Scope             `json:"scope"`
	Type              string            `json:"type"`
	Headers           map[string]string `json:"headers,omitempty"`
	CurlTemplate      string            `json:"curl_template,omitempty"`
	ImageCurlTemplate string            `json:"image_curl_template,omitempty"`
	Healthy           bool              `json:"healthy"`
	LastChecked       time.Time         `json:"last_checked"`
	IsSecurityLLM     bool              `json:"is_security_llm"`
	IsSecurityLMM     bool              `json:"is_security_lmm"`
	RegisteredAt      time.Time         `json:"registered_at,omitempty"`
}

type RegistrationHistory struct {
	Name              string    `json:"name"`
	Type              string    `json:"type"`
	Endpoint          string    `json:"endpoint"`
	CurlTemplate      string    `json:"curl_template,omitempty"`
	ImageCurlTemplate string    `json:"image_curl_template,omitempty"`
	RegisteredAt      time.Time `json:"registered_at"`
}

type Registry struct {
	mu      sync.RWMutex
	llms    map[string]*LLMObject
	history []*RegistrationHistory
	client  *http.Client
	dataDir string
}

func New(dataDir string) *Registry {
	r := &Registry{
		llms:    make(map[string]*LLMObject),
		history: make([]*RegistrationHistory, 0),
		client:  &http.Client{Timeout: 10 * time.Second},
		dataDir: dataDir,
	}
	if dataDir != "" {
		_ = os.MkdirAll(dataDir, 0700)
		_ = r.load()
		r.loadHistory()
	}
	return r
}

func extractEndpoint(curlTemplate string) string {
	for _, part := range strings.Fields(curlTemplate) {
		part = strings.Trim(part, `"'`)
		if strings.HasPrefix(part, "http://") || strings.HasPrefix(part, "https://") {
			return part
		}
	}
	return ""
}

func (r *Registry) Register(obj *LLMObject) error {
	if obj.Name == "" {
		return fmt.Errorf("name required")
	}
	if obj.CurlTemplate != "" && obj.Endpoint == "" {
		obj.Endpoint = extractEndpoint(obj.CurlTemplate)
	}
	if obj.ImageCurlTemplate != "" && obj.Endpoint == "" {
		obj.Endpoint = extractEndpoint(obj.ImageCurlTemplate)
	}
	if obj.Endpoint == "" && obj.CurlTemplate == "" && obj.ImageCurlTemplate == "" {
		return fmt.Errorf("endpoint or curl_template required")
	}
	if obj.Type == "" {
		if obj.ImageCurlTemplate != "" {
			obj.Type = "image"
		} else {
			obj.Type = "llm"
		}
	}
	if obj.RegisteredAt.IsZero() {
		obj.RegisteredAt = time.Now().UTC()
	}
	r.mu.Lock()
	r.llms[obj.Name] = obj
	r.history = append(r.history, &RegistrationHistory{
		Name:              obj.Name,
		Type:              obj.Type,
		Endpoint:          obj.Endpoint,
		CurlTemplate:      obj.CurlTemplate,
		ImageCurlTemplate: obj.ImageCurlTemplate,
		RegisteredAt:      obj.RegisteredAt,
	})
	r.mu.Unlock()
	_ = r.save()
	go r.check(obj.Name)
	return nil
}

func (r *Registry) DeleteHistory(name string, registeredAt string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, h := range r.history {
		if h.Name == name && h.RegisteredAt.UTC().Format(time.RFC3339Nano) == registeredAt {
			r.history = append(r.history[:i], r.history[i+1:]...)
			_ = r.saveHistory()
			return true
		}
	}
	return false
}

func (r *Registry) ClearHistory() {
	r.mu.Lock()
	r.history = make([]*RegistrationHistory, 0)
	_ = r.saveHistory()
	r.mu.Unlock()
}

func (r *Registry) Delete(name string) bool {
	r.mu.Lock()
	if _, ok := r.llms[name]; ok {
		delete(r.llms, name)
		r.mu.Unlock()
		_ = r.save()
		return true
	}
	r.mu.Unlock()
	return false
}

func (r *Registry) SetSecurityLLM(name string) error {
	r.mu.Lock()
	for _, l := range r.llms {
		l.IsSecurityLLM = false
	}
	if l, ok := r.llms[name]; ok {
		l.IsSecurityLLM = true
		l.Scope = ScopeInternal
		r.mu.Unlock()
		_ = r.save()
		return nil
	}
	r.mu.Unlock()
	return fmt.Errorf("LLM %q not found", name)
}

func (r *Registry) GetSecurityLLM() (*LLMObject, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, l := range r.llms {
		if l.IsSecurityLLM && l.Healthy {
			return l, nil
		}
	}
	return nil, fmt.Errorf("no healthy security LLM registered")
}

func (r *Registry) SetSecurityLMM(name string) error {
	r.mu.Lock()
	for _, l := range r.llms {
		l.IsSecurityLMM = false
	}
	if l, ok := r.llms[name]; ok {
		l.IsSecurityLMM = true
		l.Scope = ScopeInternal
		r.mu.Unlock()
		_ = r.save()
		return nil
	}
	r.mu.Unlock()
	return fmt.Errorf("LLM %q not found", name)
}

func (r *Registry) GetSecurityLMM() (*LLMObject, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, l := range r.llms {
		if l.IsSecurityLMM {
			return l, nil
		}
	}
	return nil, fmt.Errorf("no security LMM registered")
}

func (r *Registry) List() []*LLMObject {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*LLMObject, 0, len(r.llms))
	for _, l := range r.llms {
		out = append(out, l)
	}
	return out
}

func (r *Registry) ListJSON() ([]byte, error) {
	return json.Marshal(r.List())
}

func (r *Registry) History() []*RegistrationHistory {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*RegistrationHistory, 0, len(r.history))
	for i := len(r.history) - 1; i >= 0; i-- {
		out = append(out, r.history[i])
	}
	return out
}

func (r *Registry) StartHealthCheck(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.mu.RLock()
			names := make([]string, 0, len(r.llms))
			for n := range r.llms {
				names = append(names, n)
			}
			r.mu.RUnlock()
			for _, n := range names {
				r.check(n)
			}
		}
	}
}

func (r *Registry) check(name string) {
	r.mu.RLock()
	obj, ok := r.llms[name]
	r.mu.RUnlock()
	if !ok {
		return
	}
	body := []byte(`{"model":"test","messages":[{"role":"user","content":"ping"}],"max_tokens":1}`)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, obj.Endpoint+"/health", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range obj.Headers {
		req.Header.Set(k, v)
	}
	resp, err := r.client.Do(req)
	healthy := err == nil && resp.StatusCode < 500
	if resp != nil {
		resp.Body.Close()
	}
	r.mu.Lock()
	if o, ok := r.llms[name]; ok {
		o.Healthy = healthy
		o.LastChecked = time.Now()
	}
	r.mu.Unlock()
}

func (r *Registry) path() string {
	if r.dataDir == "" {
		return ""
	}
	return filepath.Join(r.dataDir, "llms.json")
}

func (r *Registry) historyPath() string {
	if r.dataDir == "" {
		return ""
	}
	return filepath.Join(r.dataDir, "history.json")
}

func (r *Registry) load() error {
	path := r.path()
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var items []*LLMObject
	if err := json.Unmarshal(raw, &items); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, item := range items {
		if item != nil && item.Name != "" {
			r.llms[item.Name] = item
		}
	}
	return nil
}

func (r *Registry) save() error {
	path := r.path()
	if path == "" {
		return nil
	}
	items := r.List()
	raw, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		return err
	}
	return r.saveHistory()
}

func (r *Registry) loadHistory() {
	path := r.historyPath()
	if path == "" {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var items []*RegistrationHistory
	if err := json.Unmarshal(raw, &items); err != nil {
		return
	}
	r.history = items
}

func (r *Registry) saveHistory() error {
	path := r.historyPath()
	if path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(r.history, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0600)
}
