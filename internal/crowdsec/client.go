package crowdsec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Client is the CrowdSec LAPI client
type Client struct {
	BaseURL    string
	APIKey     string
	MachineID  string
	Password   string
	Token      string
	HTTPClient *http.Client
}

// NewClient creates a new CrowdSec LAPI client
func NewClient(apiKey, machineID, password, baseURL string) *Client {
	return &Client{
		BaseURL:   baseURL,
		APIKey:    apiKey,
		MachineID: machineID,
		Password:  password,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Login authenticates with LAPI to get a JWT token
func (c *Client) Login() error {
	if c.MachineID == "" || c.Password == "" {
		return fmt.Errorf("machine_id and password are required for login")
	}

	endpoint := fmt.Sprintf("%s/v1/watchers/login", c.BaseURL)
	body := map[string]string{
		"machine_id": c.MachineID,
		"password":   c.Password,
	}
	jsonBody, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed with status: %d", resp.StatusCode)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	c.Token = result.Token
	return nil
}

// authMachine ensures the request is authenticated as a Machine (Watcher)
func (c *Client) authMachine(req *http.Request) error {
	// If no token, try to login
	if c.Token == "" {
		if err := c.Login(); err != nil {
			return fmt.Errorf("failed to login: %w", err)
		}
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	return nil
}

// authBouncer ensures the request is authenticated as a Bouncer
func (c *Client) authBouncer(req *http.Request) error {
	if c.APIKey == "" {
		return fmt.Errorf("API key is required for bouncer operations")
	}
	req.Header.Set("X-Api-Key", c.APIKey)
	return nil
}

// Decision represents a CrowdSec decision
type Decision struct {
	ID        int    `json:"id"`
	Origin    string `json:"origin"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Simulated bool   `json:"simulated"`
}

// Alert represents a CrowdSec alert
type Alert struct {
	ID        int    `json:"id"`
	Scenario  string `json:"scenario"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
	Source    struct {
		Scope string `json:"scope"`
		Value string `json:"value"`
	} `json:"source"`
	Decisions []Decision `json:"decisions"`
}

// GetDecisions fetches active decisions (requires Bouncer API Key)
func (c *Client) GetDecisions(opts url.Values) ([]Decision, error) {
	endpoint := fmt.Sprintf("%s/v1/decisions", c.BaseURL)
	if len(opts) > 0 {
		endpoint += "?" + opts.Encode()
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	// Decisions endpoint requires Bouncer authentication
	if err := c.authBouncer(req); err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("LAPI returned status: %d", resp.StatusCode)
	}

	var decisions []Decision
	if err := json.NewDecoder(resp.Body).Decode(&decisions); err != nil {
		return nil, err
	}

	return decisions, nil
}

// DeleteDecision deletes a decision by ID (requires Machine Auth)
func (c *Client) DeleteDecision(decisionID string) error {
	endpoint := fmt.Sprintf("%s/v1/decisions/%s", c.BaseURL, decisionID)
	req, err := http.NewRequest("DELETE", endpoint, nil)
	if err != nil {
		return err
	}

	// Delete requires Machine authentication
	if err := c.authMachine(req); err != nil {
		return err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Try to refresh token and retry once
		if err := c.Login(); err != nil {
			return fmt.Errorf("re-login failed: %w", err)
		}
		if err := c.authMachine(req); err != nil {
			return err
		}
		resp, err = c.HTTPClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("LAPI returned status: %d", resp.StatusCode)
	}

	return nil
}

// GetAlerts fetches alerts (requires Machine Auth)
func (c *Client) GetAlerts(opts url.Values) ([]Alert, error) {
	endpoint := fmt.Sprintf("%s/v1/alerts", c.BaseURL)
	if len(opts) > 0 {
		endpoint += "?" + opts.Encode()
	}

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	// Alerts endpoint requires Machine authentication
	if err := c.authMachine(req); err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Try to refresh token and retry once
		if err := c.Login(); err != nil {
			return nil, fmt.Errorf("re-login failed: %w", err)
		}
		if err := c.authMachine(req); err != nil {
			return nil, err
		}
		resp, err = c.HTTPClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("LAPI returned status: %d", resp.StatusCode)
	}

	var alerts []Alert
	if err := json.NewDecoder(resp.Body).Decode(&alerts); err != nil {
		return nil, err
	}

	return alerts, nil
}

// GetMetrics fetches metrics (Not implemented in client, handled via cscli in handler)
func (c *Client) GetMetrics() (map[string]interface{}, error) {
	return nil, fmt.Errorf("not implemented")
}
