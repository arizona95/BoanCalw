package guac

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/samsung-sds/boanclaw/boan-proxy/internal/config"
	"github.com/samsung-sds/boanclaw/boan-proxy/internal/userstore"
)

type Client struct {
	baseURL  string
	basePath string
	username string
	password string
	client   *http.Client
}

type tokenResponse struct {
	AuthToken  string `json:"authToken"`
	DataSource string `json:"dataSource"`
}

type connection struct {
	Identifier string `json:"identifier"`
	Name       string `json:"name"`
}

func New(cfg *config.Config) *Client {
	return &Client{
		baseURL:  strings.TrimRight(cfg.GuacamoleURL, "/"),
		basePath: strings.TrimRight(cfg.GuacamoleBasePath, "/"),
		username: cfg.GuacamoleUsername,
		password: cfg.GuacamolePassword,
		client:   &http.Client{},
	}
}

func (c *Client) Enabled() bool {
	return c.baseURL != "" && c.username != "" && c.password != ""
}

func (c *Client) EnsureSessionURL(ctx context.Context, ws *userstore.Workstation) (string, error) {
	if !c.Enabled() || ws == nil {
		return "", nil
	}
	if strings.TrimSpace(ws.RemoteHost) == "" || strings.TrimSpace(ws.RemoteUser) == "" || strings.TrimSpace(ws.RemotePass) == "" {
		return "", nil
	}

	authToken, dataSource, err := c.login(ctx)
	if err != nil {
		return "", err
	}

	connectionID, err := c.ensureConnection(ctx, authToken, dataSource, ws)
	if err != nil {
		return "", err
	}

	clientID := base64.StdEncoding.EncodeToString([]byte(connectionID + "\x00c\x00" + dataSource))
	return fmt.Sprintf("%s/#/client/%s?token=%s", c.basePath, clientID, authToken), nil
}

func (c *Client) login(ctx context.Context) (string, string, error) {
	form := url.Values{}
	form.Set("username", c.username)
	form.Set("password", c.password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/tokens", strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", "", fmt.Errorf("guacamole login returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var out tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", err
	}
	if out.AuthToken == "" || out.DataSource == "" {
		return "", "", fmt.Errorf("guacamole login returned empty token or data source")
	}
	return out.AuthToken, out.DataSource, nil
}

func (c *Client) ensureConnection(ctx context.Context, token, dataSource string, ws *userstore.Workstation) (string, error) {
	name := ws.DisplayName
	connections, err := c.listConnections(ctx, token, dataSource)
	if err != nil {
		return "", err
	}
	if existingID := findConnectionID(connections, name); existingID != "" {
		if err := c.updateConnection(ctx, token, dataSource, existingID, ws); err != nil {
			return "", err
		}
		return existingID, nil
	}
	return c.createConnection(ctx, token, dataSource, ws)
}

func (c *Client) listConnections(ctx context.Context, token, dataSource string) (map[string]connection, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/session/data/%s/connections?token=%s", c.baseURL, dataSource, url.QueryEscape(token)), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("guacamole list connections returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	out := map[string]connection{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) createConnection(ctx context.Context, token, dataSource string, ws *userstore.Workstation) (string, error) {
	body, err := json.Marshal(connectionPayload(ws))
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/api/session/data/%s/connections?token=%s", c.baseURL, dataSource, url.QueryEscape(token)), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("guacamole create connection returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out connection
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Identifier == "" {
		return "", fmt.Errorf("guacamole create connection returned empty identifier")
	}
	return out.Identifier, nil
}

func (c *Client) updateConnection(ctx context.Context, token, dataSource, id string, ws *userstore.Workstation) error {
	body, err := json.Marshal(connectionPayload(ws))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, fmt.Sprintf("%s/api/session/data/%s/connections/%s?token=%s", c.baseURL, dataSource, id, url.QueryEscape(token)), bytes.NewReader(body))
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("guacamole update connection returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func connectionPayload(ws *userstore.Workstation) map[string]any {
	port := ws.RemotePort
	if port == 0 {
		port = 3389
	}
	return map[string]any{
		"parentIdentifier": "ROOT",
		"name":             ws.DisplayName,
		"protocol":         "rdp",
		"attributes": map[string]string{
			"max-connections":          "",
			"max-connections-per-user": "",
			"weight":                   "",
			"failover-only":            "",
			"guacd-hostname":           "",
			"guacd-port":               "",
			"guacd-encryption":         "",
		},
		"parameters": map[string]string{
			"hostname":         ws.RemoteHost,
			"port":             fmt.Sprintf("%d", port),
			"username":         ws.RemoteUser,
			"password":         ws.RemotePass,
			"security":         "any",
			"ignore-cert":      "true",
			"resize-method":    "display-update",
			"disable-copy":     "false",
			"disable-paste":    "false",
			"enable-wallpaper": "true",
			"enable-theming":   "true",
		},
	}
}

func findConnectionID(connections map[string]connection, name string) string {
	for _, conn := range connections {
		if conn.Name == name {
			if conn.Identifier != "" {
				return conn.Identifier
			}
		}
	}
	for id, conn := range connections {
		if conn.Name == name {
			return id
		}
	}
	return ""
}
