package orgserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	token   string
	client  *http.Client
}

type User struct {
	Email        string       `json:"email"`
	Name         string       `json:"name"`
	MachineID    string       `json:"machine_id,omitempty"`
	MachineName  string       `json:"machine_name,omitempty"`
	Role         string       `json:"role"`
	OrgID        string       `json:"org_id"`
	Status       string       `json:"status"`
	RegisteredIP string       `json:"registered_ip,omitempty"`
	Workstation  *Workstation `json:"workstation,omitempty"`
}

type Workstation struct {
	Provider      string `json:"provider"`
	Platform      string `json:"platform"`
	Status        string `json:"status"`
	DisplayName   string `json:"display_name"`
	InstanceID    string `json:"instance_id"`
	Region        string `json:"region,omitempty"`
	ConsoleURL    string `json:"console_url,omitempty"`
	WebDesktopURL string `json:"web_desktop_url,omitempty"`
	AssignedAt    string `json:"assigned_at,omitempty"`
}

func New(baseURL string) *Client {
	return NewWithToken(baseURL, "")
}

func NewWithToken(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// SetToken: 런타임에 토큰 갱신 (멀티 조직 전환용).
func (c *Client) SetToken(token string) { c.token = token }

// authedRequest: Bearer 헤더 자동 첨부.
func (c *Client) authedRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return req, nil
}

// authedGet / authedPost 헬퍼.
func (c *Client) authedGet(url string) (*http.Response, error) {
	req, err := c.authedRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.client.Do(req)
}

func (c *Client) authedPost(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := c.authedRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.client.Do(req)
}

func (c *Client) Enabled() bool {
	return c != nil && c.baseURL != ""
}

func (c *Client) ListUsers(orgID string) ([]User, error) {
	if !c.Enabled() {
		return nil, nil
	}
	resp, err := c.authedGet(fmt.Sprintf("%s/org/%s/v1/users", c.baseURL, orgID))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("org server returned status %d", resp.StatusCode)
	}
	var users []User
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, err
	}
	return users, nil
}

func (c *Client) RegisterUser(orgID, email, password string) error {
	return c.RegisterUserWithState(orgID, email, password, "", "", "", "")
}

func (c *Client) RegisterUserWithState(orgID, email, password, role, status, machineID, machineName string) error {
	if !c.Enabled() {
		return nil
	}
	body := map[string]string{
		"email":    email,
		"password": password,
		"role":     role,
		"status":   status,
		"machine_id": machineID,
		"machine_name": machineName,
	}
	return c.postJSON(fmt.Sprintf("%s/org/%s/v1/users/register", c.baseURL, orgID), body)
}

func (c *Client) SyncSSOUser(orgID, email, name, role, provider string) error {
	return c.SyncUser(orgID, email, name, role, provider, "", "", "")
}

func (c *Client) SyncUser(orgID, email, name, role, provider, status, machineID, machineName string) error {
	if !c.Enabled() {
		return nil
	}
	body := map[string]string{
		"email":    email,
		"name":     name,
		"role":     role,
		"provider": provider,
		"status":   status,
		"machine_id": machineID,
		"machine_name": machineName,
	}
	return c.postJSON(fmt.Sprintf("%s/org/%s/v1/users/sso-sync", c.baseURL, orgID), body)
}

func (c *Client) UpdateUser(orgID, email, role, status, accessLevel string, workstation *Workstation, machineID, machineName string) error {
	if !c.Enabled() {
		return nil
	}
	body := map[string]any{
		"email":        email,
		"role":         role,
		"status":       status,
		"access_level": accessLevel,
		"workstation":  workstation,
		"machine_id":   machineID,
		"machine_name": machineName,
	}
	return c.doJSON(http.MethodPatch, fmt.Sprintf("%s/org/%s/v1/users", c.baseURL, orgID), body)
}

func (c *Client) ProposeAmendment(orgID string) (map[string]any, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("org server not configured")
	}
	url := fmt.Sprintf("%s/org/%s/v1/guardrail/propose-amendment", c.baseURL, orgID)
	raw, _ := json.Marshal(map[string]string{})
	req, err := c.authedRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("propose-amendment returned %d: %s", resp.StatusCode, string(body))
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func (c *Client) AppendTrainingLog(orgID string, entry map[string]any) error {
	if !c.Enabled() {
		return nil
	}
	return c.doJSON(http.MethodPost, fmt.Sprintf("%s/org/%s/v1/guardrail/training-log", c.baseURL, orgID), entry)
}

func (c *Client) ProposeG1Amendment(orgID string) (map[string]any, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("org server not configured")
	}
	url := fmt.Sprintf("%s/org/%s/v1/guardrail/propose-g1-amendment", c.baseURL, orgID)
	raw, _ := json.Marshal(map[string]string{})
	req, err := c.authedRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("propose-g1-amendment returned %d: %s", resp.StatusCode, string(body))
	}
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func (c *Client) UpdatePolicy(orgID string, update map[string]any) error {
	if !c.Enabled() {
		return nil
	}
	return c.doJSON(http.MethodPut, fmt.Sprintf("%s/org/%s/v1/policy", c.baseURL, orgID), update)
}

func (c *Client) GetTrainingLog(orgID string) ([]map[string]any, error) {
	if !c.Enabled() {
		return nil, nil
	}
	url := fmt.Sprintf("%s/org/%s/v1/guardrail/training-log", c.baseURL, orgID)
	resp, err := c.authedGet(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var entries []map[string]any
	json.NewDecoder(resp.Body).Decode(&entries)
	return entries, nil
}

func (c *Client) CompileWiki(orgID string) error {
	return c.CompileWikiWithLLM(orgID, "", "")
}

func (c *Client) CompileWikiWithLLM(orgID, llmURL, llmModel string) error {
	if !c.Enabled() {
		return fmt.Errorf("org server not configured")
	}
	body := map[string]string{}
	if llmURL != "" {
		body["llm_url"] = llmURL
	}
	if llmModel != "" {
		body["llm_model"] = llmModel
	}
	return c.postJSON(fmt.Sprintf("%s/org/%s/v1/wiki/compile", c.baseURL, orgID), body)
}

func (c *Client) GetWikiIndex(orgID string) (map[string]any, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("org server not configured")
	}
	url := fmt.Sprintf("%s/org/%s/v1/wiki", c.baseURL, orgID)
	resp, err := c.authedGet(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

func (c *Client) GetWikiPages(orgID string) ([]map[string]any, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("org server not configured")
	}
	url := fmt.Sprintf("%s/org/%s/v1/wiki/pages", c.baseURL, orgID)
	resp, err := c.authedGet(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result []map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

// CheckLoginIP — TOFU IP 바인딩 확인.
// 반환: allowed (로그인 허용 여부), reason ("captured"|"match"|"ip_mismatch"|"user_not_found").
// 에러 시 (org-server 불통 등): fail-closed (allowed=false).
func (c *Client) CheckLoginIP(orgID, email, clientIP string) (bool, string, error) {
	if !c.Enabled() {
		return false, "org_server_disabled", nil
	}
	body, _ := json.Marshal(map[string]string{"email": email, "client_ip": clientIP})
	resp, err := c.authedPost(
		fmt.Sprintf("%s/org/%s/v1/users/check-login-ip", c.baseURL, orgID),
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return false, "network_error: " + err.Error(), err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, fmt.Sprintf("org_server_status_%d", resp.StatusCode), nil
	}
	var out struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, "decode_error", err
	}
	return out.Allowed, out.Reason, nil
}

// ResetUserIP — 관리자용: 사용자의 RegisteredIP 초기화.
func (c *Client) ResetUserIP(orgID, email string) error {
	if !c.Enabled() {
		return nil
	}
	return c.postJSON(
		fmt.Sprintf("%s/org/%s/v1/users/reset-ip", c.baseURL, orgID),
		map[string]string{"email": email},
	)
}

func (c *Client) DeleteUser(orgID, email string) error {
	if !c.Enabled() {
		return nil
	}
	return c.doJSON(http.MethodDelete, fmt.Sprintf("%s/org/%s/v1/users", c.baseURL, orgID), map[string]string{"email": email})
}

func (c *Client) postJSON(url string, body any) error {
	return c.doJSON(http.MethodPost, url, body)
}

func (c *Client) doJSON(method, url string, body any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := c.authedRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("org server returned status %d", resp.StatusCode)
	}
	return nil
}
