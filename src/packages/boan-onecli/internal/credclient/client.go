package credclient

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type credResponse struct {
	Value     string    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}

type cachedCred struct {
	value     string
	expiresAt time.Time
	fetchedAt time.Time
}

type Client struct {
	baseURL        string
	orgID          string
	credentialName string
	credentialType string
	httpClient     *http.Client

	mu    sync.Mutex
	cache *cachedCred
}

func New(baseURL, orgID, name, credType string) *Client {
	return &Client{
		baseURL:        baseURL,
		orgID:          orgID,
		credentialName: name,
		credentialType: credType,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) credential() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	if c.cache != nil {
		refreshBefore := c.cache.expiresAt.Add(-30 * time.Second)
		if now.Before(refreshBefore) {
			return c.cache.value, nil
		}
	}

	url := fmt.Sprintf("%s/credential/%s/%s", c.baseURL, c.orgID, c.credentialName)
	resp, err := c.httpClient.Get(url)
	if err != nil {
		if c.cache != nil {
			return c.cache.value, nil
		}
		return "", fmt.Errorf("fetching credential: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("credential filter returned %d: %s", resp.StatusCode, string(body))
	}

	var cr credResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return "", fmt.Errorf("decoding credential response: %w", err)
	}

	expiry := cr.ExpiresAt
	if expiry.IsZero() {
		expiry = now.Add(5 * time.Minute)
	}
	c.cache = &cachedCred{value: cr.Value, expiresAt: expiry, fetchedAt: now}
	return cr.Value, nil
}

func (c *Client) InjectHeader(r *http.Request) error {
	val, err := c.credential()
	if err != nil {
		return err
	}

	switch c.credentialType {
	case "api_key":
		r.Header.Set("x-api-key", val)
	case "bearer":
		r.Header.Set("Authorization", "Bearer "+val)
	case "aws_sigv4":
		// TODO: AWS SigV4 signing via AWS SDK
	case "azure_ad":
		// TODO: Azure AD token refresh
	case "gcp_sa":
		// TODO: GCP Service Account token
	default:
		r.Header.Set("x-api-key", val)
	}
	return nil
}
