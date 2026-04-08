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
	client  *http.Client
}

type User struct {
	Email       string       `json:"email"`
	Name        string       `json:"name"`
	MachineID   string       `json:"machine_id,omitempty"`
	MachineName string       `json:"machine_name,omitempty"`
	Role        string       `json:"role"`
	OrgID       string       `json:"org_id"`
	Status      string       `json:"status"`
	Workstation *Workstation `json:"workstation,omitempty"`
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
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) Enabled() bool {
	return c != nil && c.baseURL != ""
}

func (c *Client) ListUsers(orgID string) ([]User, error) {
	if !c.Enabled() {
		return nil, nil
	}
	resp, err := c.client.Get(fmt.Sprintf("%s/org/%s/v1/users", c.baseURL, orgID))
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
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
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
	req, err := http.NewRequest(method, url, bytes.NewReader(raw))
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
