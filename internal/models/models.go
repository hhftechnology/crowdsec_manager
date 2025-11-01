package models

import "time"

// Response is the standard API response
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// Container represents a Docker container
type Container struct {
	Name    string `json:"name"`
	ID      string `json:"id"`
	Status  string `json:"status"`
	Running bool   `json:"running"`
}

// HealthStatus represents system health status
type HealthStatus struct {
	Containers []Container `json:"containers"`
	AllRunning bool        `json:"allRunning"`
	Timestamp  time.Time   `json:"timestamp"`
}

// Decision represents a CrowdSec decision
type Decision struct {
	ID        int64  `json:"id"`
	Source    string `json:"source"`    // Changed from "origin" to "source"
	Type      string `json:"type"`      // This is the decision type (ban, captcha, etc.)
	Scope     string `json:"scope"`     // This should be correct
	Value     string `json:"value"`     // This should be correct
	Duration  string `json:"duration"`  // This should be correct
	Scenario  string `json:"scenario"`  // Changed from "scenario" - let's check if it's "reason"
	CreatedAt string `json:"created_at"` // Changed from time.Time to string for flexibility

	// Alternative field names that CrowdSec might use
	Reason    string `json:"reason,omitempty"`    // CrowdSec might call scenario "reason"
	Origin    string `json:"origin,omitempty"`    // Backup field name
	Until     string `json:"until,omitempty"`     // Expiration timestamp
	Simulated *bool  `json:"simulated,omitempty"` // Whether decision is simulated
	UUID      string `json:"uuid,omitempty"`      // Unique identifier for LAPI→CAPI
}

// DecisionRaw is the raw structure from CrowdSec JSON output
// This matches CrowdSec's actual JSON field names
type DecisionRaw struct {
	ID        int64  `json:"id"`
	Source    string `json:"source"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Reason    string `json:"reason"` // CrowdSec uses "reason" for the scenario
	CreatedAt string `json:"created_at"`
	Origin    string `json:"origin"`
}

// Normalize converts DecisionRaw to Decision with normalized fields
func (d *DecisionRaw) Normalize() Decision {
	// Use Reason if Scenario is empty
	scenario := d.Scenario
	if scenario == "" && d.Reason != "" {
		scenario = d.Reason
	}

	// Use Source if Origin is empty
	origin := d.Source
	if origin == "" && d.Origin != "" {
		origin = d.Origin
	}

	return Decision{
		ID:        d.ID,
		Source:    origin,
		Type:      d.Type,
		Scope:     d.Scope,
		Value:     d.Value,
		Duration:  d.Duration,
		Scenario:  scenario,
		CreatedAt: d.CreatedAt,
		Origin:    origin,
		Reason:    scenario,
	}
}

// Bouncer represents a CrowdSec bouncer
type Bouncer struct {
	Name      string    `json:"name"`
	IPAddress string    `json:"ip_address"`
	Valid     bool      `json:"valid"`
	LastPull  time.Time `json:"last_pull"`
	Type      string    `json:"type"`
	Version   string    `json:"version"`
	Status    string    `json:"status"`
}

// IPInfo represents IP address information
type IPInfo struct {
	IP          string `json:"ip"`
	IsBlocked   bool   `json:"is_blocked"`
	IsWhitelisted bool `json:"is_whitelisted"`
	InCrowdSec  bool   `json:"in_crowdsec"`
	InTraefik   bool   `json:"in_traefik"`
}

// WhitelistRequest represents a whitelist request
type WhitelistRequest struct {
	IP             string `json:"ip"`
	CIDR           string `json:"cidr,omitempty"`
	AddToCrowdSec  bool   `json:"add_to_crowdsec"`
	AddToTraefik   bool   `json:"add_to_traefik"`
	Comprehensive  bool   `json:"comprehensive,omitempty"`
}

// Backup represents a backup
type Backup struct {
	ID        string    `json:"id"`
	Filename  string    `json:"filename"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"created_at"`
}

// BackupRequest represents a backup request
type BackupRequest struct {
	Items   []string `json:"items,omitempty"`
	DryRun  bool     `json:"dry_run"`
}

// RestoreRequest represents a restore request
type RestoreRequest struct {
	BackupID string `json:"backup_id"`
	Confirm  bool   `json:"confirm"`
}

// UpdateRequest represents an update request
type UpdateRequest struct {
	PangolinTag      string `json:"pangolin_tag,omitempty"`
	GerbilTag        string `json:"gerbil_tag,omitempty"`
	TraefikTag       string `json:"traefik_tag,omitempty"`
	CrowdSecTag      string `json:"crowdsec_tag,omitempty"`
	IncludeCrowdSec  bool   `json:"include_crowdsec"`
}

// ImageTags represents current Docker image tags
type ImageTags struct {
	Pangolin string `json:"pangolin"`
	Gerbil   string `json:"gerbil"`
	Traefik  string `json:"traefik"`
	CrowdSec string `json:"crowdsec,omitempty"`
}

// LogEntry represents a log entry
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Service   string    `json:"service"`
	Message   string    `json:"message"`
}

// LogStats represents log statistics
type LogStats struct {
	TotalLines   int                       `json:"total_lines"`
	TopIPs       []IPCount                 `json:"top_ips"`
	StatusCodes  map[string]int            `json:"status_codes"`
	HTTPMethods  map[string]int            `json:"http_methods"`
	ErrorEntries []LogEntry                `json:"error_entries"`
}

// IPCount represents IP address count
type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// ScenarioSetupRequest represents custom scenario setup request
type ScenarioSetupRequest struct {
	Scenarios []Scenario `json:"scenarios"`
}

// Scenario represents a CrowdSec scenario
type Scenario struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Content     string `json:"content"`
}

// CaptchaSetupRequest represents captcha setup request
type CaptchaSetupRequest struct {
	Provider  string `json:"provider"`
	SiteKey   string `json:"site_key"`
	SecretKey string `json:"secret_key"`
}

// CronJobRequest represents a cron job setup request
type CronJobRequest struct {
	Schedule string `json:"schedule"`
	Task     string `json:"task"`
}

// Metric represents a Prometheus metric
type Metric struct {
	Name  string            `json:"name"`
	Value float64           `json:"value"`
	Labels map[string]string `json:"labels,omitempty"`
}

// TraefikIntegration represents Traefik-CrowdSec integration status
type TraefikIntegration struct {
	MiddlewareConfigured bool     `json:"middleware_configured"`
	ConfigFiles          []string `json:"config_files"`
	LapiKeyFound         bool     `json:"lapi_key_found"`
	AppsecEnabled        bool     `json:"appsec_enabled"`
	CaptchaEnabled       bool     `json:"captcha_enabled"`
	CaptchaProvider      string   `json:"captcha_provider,omitempty"`
	CaptchaHTMLExists    bool     `json:"captcha_html_exists"`
}

// DiagnosticResult represents complete diagnostic results
type DiagnosticResult struct {
	Health             *HealthStatus       `json:"health"`
	Bouncers           []Bouncer           `json:"bouncers"`
	Decisions          []Decision          `json:"decisions"`
	TraefikIntegration *TraefikIntegration `json:"traefik_integration"`
	Timestamp          time.Time           `json:"timestamp"`
}

// UnbanRequest represents an unban request
type UnbanRequest struct {
	IP string `json:"ip" binding:"required"`
}

// ServiceAction represents a service action (start/stop/restart)
type ServiceAction struct {
	Service string `json:"service" binding:"required"`
	Action  string `json:"action" binding:"required"` // start, stop, restart
}

// ConfigPathRequest represents a configuration path update request
type ConfigPathRequest struct {
	DynamicConfigPath string `json:"dynamic_config_path" binding:"required"`
}

// Allowlist represents a CrowdSec allowlist
type Allowlist struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
}

// AllowlistEntry represents an entry in an allowlist
type AllowlistEntry struct {
	Value       string    `json:"value"`        // IP or CIDR range
	Description string    `json:"description"`  // Optional entry description
	Expiration  string    `json:"expiration"`   // Optional expiration (e.g., "7d")
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

// AllowlistCreateRequest represents a request to create a new allowlist
type AllowlistCreateRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description" binding:"required"`
}

// AllowlistAddEntriesRequest represents a request to add entries to an allowlist
type AllowlistAddEntriesRequest struct {
	AllowlistName string   `json:"allowlist_name" binding:"required"`
	Values        []string `json:"values" binding:"required"`
	Expiration    string   `json:"expiration,omitempty"`    // Optional expiration (e.g., "7d")
	Description   string   `json:"description,omitempty"`   // Optional entry description
}

// AllowlistRemoveEntriesRequest represents a request to remove entries from an allowlist
type AllowlistRemoveEntriesRequest struct {
	AllowlistName string   `json:"allowlist_name" binding:"required"`
	Values        []string `json:"values" binding:"required"`
}

// AllowlistInspectResponse represents the detailed information about an allowlist
type AllowlistInspectResponse struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Entries     []AllowlistEntry `json:"entries"`
	Count       int              `json:"count"`
}
