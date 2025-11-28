package crowdsec

import (
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
	HTTPClient *http.Client
}

// NewClient creates a new CrowdSec LAPI client
func NewClient(apiKey string, baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
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

// GetDecisions fetches decisions from LAPI
func (c *Client) GetDecisions(opts url.Values) ([]Decision, error) {
	endpoint := fmt.Sprintf("%s/v1/decisions", c.BaseURL)
	
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	if opts != nil {
		req.URL.RawQuery = opts.Encode()
	}

	req.Header.Add("X-Api-Key", c.APIKey)

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

// DeleteDecision deletes a decision via LAPI
func (c *Client) DeleteDecision(ip string, id string) error {
	endpoint := fmt.Sprintf("%s/v1/decisions", c.BaseURL)
	if id != "" {
		endpoint = fmt.Sprintf("%s/%s", endpoint, id)
	}

	req, err := http.NewRequest("DELETE", endpoint, nil)
	if err != nil {
		return err
	}

	if id == "" && ip != "" {
		q := req.URL.Query()
		q.Add("ip", ip)
		req.URL.RawQuery = q.Encode()
	}

	req.Header.Add("X-Api-Key", c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("LAPI returned status: %d", resp.StatusCode)
	}

	return nil
}

// GetAlerts fetches alerts from LAPI
func (c *Client) GetAlerts(opts url.Values) ([]Alert, error) {
	endpoint := fmt.Sprintf("%s/v1/alerts", c.BaseURL)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}

	if opts != nil {
		req.URL.RawQuery = opts.Encode()
	}

	req.Header.Add("X-Api-Key", c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("LAPI returned status: %d", resp.StatusCode)
	}

	var alerts []Alert
	if err := json.NewDecoder(resp.Body).Decode(&alerts); err != nil {
		return nil, err
	}

	return alerts, nil
}

// GetMetrics fetches metrics from Prometheus endpoint
func (c *Client) GetMetrics() (map[string]interface{}, error) {
	// Note: Metrics are usually exposed on port 6060, not the LAPI port (8080)
	// We might need a separate URL for metrics if it differs from BaseURL
	// For now, assuming we can construct it or pass it.
	// Actually, the plan said GET /metrics (Prometheus).
	// If BaseURL is http://crowdsec:8080, metrics might be http://crowdsec:6060/metrics
	
	// Let's assume the user configures the full LAPI URL, but metrics is separate.
	// For simplicity, let's try to derive it or use a separate config if needed.
	// But `cscli metrics` uses http://localhost:6060/metrics by default.
	
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, err
	}
	
	// Hack: Change port to 6060 for metrics if it's 8080
	// This is a simplification. Ideally, we'd have a separate config.
	// But for now, let's stick to what `cscli` does (it defaults to localhost:6060)
	
	metricsURL := fmt.Sprintf("%s://%s:6060/metrics", u.Scheme, u.Hostname())
	
	req, err := http.NewRequest("GET", metricsURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics returned status: %d", resp.StatusCode)
	}

	// Prometheus format is text, not JSON by default unless we use a specific endpoint or parser.
	// Wait, cscli metrics -o json parses it.
	// We need to parse Prometheus text format to JSON or map.
	// Or we can just return the raw string if we want to mimic the previous behavior?
	// But the plan said "Parse JSON metrics".
	// `cscli metrics -o json` does the parsing.
	// If we hit the endpoint directly, we get text.
	// We might need a prometheus parser.
	
	// For now, let's return an error saying not implemented fully or just return raw data?
	// Actually, `cscli metrics` is complex.
	// Maybe we should stick to `cscli metrics -o json` for now as per the "Non-Migratable" list?
	// Wait, the plan said "Migratable? Yes".
	// But parsing prometheus metrics in Go without a library is annoying.
	// Let's stick to `cscli metrics -o json` for metrics for now to avoid complexity, 
	// OR we can use a simple parser if we really want to remove cscli.
	
	// Re-reading plan: "Replace ExecCommand... with client.GetMetrics()".
	// If I implement `GetMetrics` here, I need to parse it.
	// Let's skip `GetMetrics` implementation in this file for now and keep using `cscli` for metrics 
	// until we decide on a parser library, OR I can implement a basic parser.
	
	return nil, fmt.Errorf("not implemented")
}
