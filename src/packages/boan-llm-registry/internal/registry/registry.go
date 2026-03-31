package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
}

type Registry struct {
	mu     sync.RWMutex
	llms   map[string]*LLMObject
	client *http.Client
}

func New() *Registry {
	return &Registry{
		llms:   make(map[string]*LLMObject),
		client: &http.Client{Timeout: 10 * time.Second},
	}
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
	r.mu.Lock()
	r.llms[obj.Name] = obj
	r.mu.Unlock()
	go r.check(obj.Name)
	return nil
}

func (r *Registry) Delete(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.llms[name]; ok {
		delete(r.llms, name)
		return true
	}
	return false
}

func (r *Registry) SetSecurityLLM(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, l := range r.llms {
		l.IsSecurityLLM = false
	}
	if l, ok := r.llms[name]; ok {
		l.IsSecurityLLM = true
		l.Scope = ScopeInternal
		return nil
	}
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
