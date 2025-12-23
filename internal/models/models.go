package models

import (
	"fmt"
	"time"
)

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

// HealthCheckItem represents a single health check item
type HealthCheckItem struct {
	Status  string                 `json:"status"`            // healthy, unhealthy, degraded, warning, info
	Message string                 `json:"message"`           // Human-readable message
	Error   string                 `json:"error,omitempty"`   // Error details if check failed
	Details string                 `json:"details,omitempty"` // Additional details
	Metrics map[string]interface{} `json:"metrics,omitempty"` // Structured metrics data
}

// CrowdSecHealthCheck represents the complete CrowdSec Security Engine health status
type CrowdSecHealthCheck struct {
	Status    string                     `json:"status"`    // Overall status: healthy, degraded, unhealthy
	Timestamp time.Time                  `json:"timestamp"` // When the check was performed
	Checks    map[string]HealthCheckItem `json:"checks"`    // Individual health checks
}

// Alert represents a CrowdSec alert that contains decisions
type Alert struct {
	Capacity  int                      `json:"capacity"`
	CreatedAt string                   `json:"created_at"`
	Decisions []Decision               `json:"decisions"`
	Events    []map[string]interface{} `json:"events,omitempty"`
}

// Decision represents a CrowdSec decision
type Decision struct {
	ID        int64  `json:"id"`
	AlertID   int64  `json:"alert_id"`           // ID of the parent alert
	Origin    string `json:"origin"`             // Source of the decision (crowdsec, cscli, etc.)
	Type      string `json:"type"`               // Decision type (ban, captcha, etc.)
	Scope     string `json:"scope"`              // Scope (Ip, Range, etc.)
	Value     string `json:"value"`              // IP address or range
	Duration  string `json:"duration"`           // Duration like "3h45m3s"
	Scenario  string `json:"scenario"`           // Scenario name
	Simulated bool   `json:"simulated"`          // Whether decision is simulated
	CreatedAt string `json:"created_at"`         // Creation timestamp

	// Legacy/additional fields for backward compatibility
	Source    string `json:"source,omitempty"`   // Alias for Origin (backward compat)
	Reason    string `json:"reason,omitempty"`   // Alias for Scenario (some versions use this)
	Until     string `json:"until,omitempty"`    // Expiration timestamp
	UUID      string `json:"uuid,omitempty"`     // Unique identifier
}

// DecisionRaw is the raw structure from CrowdSec JSON output
// This matches CrowdSec's actual JSON field names
type DecisionRaw struct {
	ID        int64       `json:"id"`
	Source    interface{} `json:"source"` // Changed to interface{} as it can be a string or object
	Type      string      `json:"type"`
	Scope     string      `json:"scope"`
	Value     string      `json:"value"`
	Duration  string      `json:"duration"`
	Scenario  string      `json:"scenario"`
	Reason    string      `json:"reason"` // CrowdSec uses "reason" for the scenario
	CreatedAt string      `json:"created_at"`
	Origin    string      `json:"origin"`
}

// Normalize converts DecisionRaw to Decision with normalized fields
func (d *DecisionRaw) Normalize() Decision {
	// Use Reason if Scenario is empty
	scenario := d.Scenario
	if scenario == "" && d.Reason != "" {
		scenario = d.Reason
	}

	// Handle Source which can be string or object
	var sourceStr string
	switch v := d.Source.(type) {
	case string:
		sourceStr = v
	case map[string]interface{}:
		// Try to find a meaningful name in the object
		if name, ok := v["name"].(string); ok {
			sourceStr = name
		} else if typeStr, ok := v["type"].(string); ok {
			sourceStr = typeStr
		} else {
			// Fallback to generic string, but we'll check Origin later
			sourceStr = "unknown_source_object"
		}
	case nil:
		sourceStr = ""
	default:
		sourceStr = fmt.Sprintf("%v", v)
	}

	// Use Origin if Source is empty or generic/unknown
	origin := d.Origin
	if origin == "" || sourceStr != "unknown_source_object" {
		// If Origin is empty, OR if we found a good Source, use Source
		// But if Source is "unknown_source_object" and we have an Origin, keep Origin
		if sourceStr != "" && sourceStr != "unknown_source_object" {
			origin = sourceStr
		}
	}
	
	// If we still have unknown source object and no origin, try to be cleaner
	if origin == "" && sourceStr == "unknown_source_object" {
		origin = "unknown"
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
	Revoked   bool      `json:"revoked"`
	Valid     bool      `json:"valid"`
	LastPull  time.Time `json:"last_pull"`
	Type      string    `json:"type"`
	Version   string    `json:"version"`
	Status    string    `json:"status"`
}

// IPInfo represents IP address information
type IPInfo struct {
	IP            string `json:"ip"`
	IsBlocked     bool   `json:"is_blocked"`
	IsWhitelisted bool   `json:"is_whitelisted"`
	InCrowdSec    bool   `json:"in_crowdsec"`
	InTraefik     bool   `json:"in_traefik"`
}

// WhitelistRequest represents a whitelist request
type WhitelistRequest struct {
	IP            string `json:"ip"`
	CIDR          string `json:"cidr,omitempty"`
	AddToCrowdSec bool   `json:"add_to_crowdsec"`
	AddToTraefik  bool   `json:"add_to_traefik"`
	Comprehensive bool   `json:"comprehensive,omitempty"`
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
	Items  []string `json:"items,omitempty"`
	DryRun bool     `json:"dry_run"`
}

// RestoreRequest represents a restore request
type RestoreRequest struct {
	BackupID string `json:"backup_id"`
	Confirm  bool   `json:"confirm"`
}

// UpdateRequest represents an update request
type UpdateRequest struct {
	PangolinTag     string `json:"pangolin_tag,omitempty"`
	GerbilTag       string `json:"gerbil_tag,omitempty"`
	TraefikTag      string `json:"traefik_tag,omitempty"`
	CrowdSecTag     string `json:"crowdsec_tag,omitempty"`
	IncludeCrowdSec bool   `json:"include_crowdsec"`
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
	TotalLines   int            `json:"total_lines"`
	TopIPs       []IPCount      `json:"top_ips"`
	StatusCodes  map[string]int `json:"status_codes"`
	HTTPMethods  map[string]int `json:"http_methods"`
	ErrorEntries []LogEntry     `json:"error_entries"`
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
	Name   string            `json:"name"`
	Value  float64           `json:"value"`
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
	Name        string           `json:"name"`
	Description string           `json:"description"`
	CreatedAt   string           `json:"created_at,omitempty"`
	UpdatedAt   string           `json:"updated_at,omitempty"`
	Items       []AllowlistEntry `json:"items,omitempty"`
	Size        int              `json:"size,omitempty"` // Computed from Items length
}

// AllowlistEntry represents an entry in an allowlist
// This structure matches CrowdSec's actual JSON output
type AllowlistEntry struct {
	Value      string    `json:"value"`      // IP or CIDR range
	CreatedAt  time.Time `json:"created_at"` // When the entry was added
	Expiration string    `json:"expiration"` // Expiration date (ISO format or "0001-01-01T00:00:00.000Z" for never)
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
	Expiration    string   `json:"expiration,omitempty"`  // Optional expiration (e.g., "7d")
	Description   string   `json:"description,omitempty"` // Optional entry description (for CLI, not stored per-entry)
}

// AllowlistRemoveEntriesRequest represents a request to remove entries from an allowlist
type AllowlistRemoveEntriesRequest struct {
	AllowlistName string   `json:"allowlist_name" binding:"required"`
	Values        []string `json:"values" binding:"required"`
}

// AllowlistInspectResponse represents the detailed information about an allowlist
// This structure matches CrowdSec's actual JSON output from "cscli allowlists inspect -o json"
type AllowlistInspectResponse struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Items       []AllowlistEntry `json:"items"`      // CrowdSec uses "items", not "entries"
	CreatedAt   string           `json:"created_at"` // When the allowlist was created
	UpdatedAt   string           `json:"updated_at"` // When the allowlist was last updated
	Count       int              `json:"count,omitempty"` // Number of items
}

// DiscordConfig represents the configuration for Discord notifications
type DiscordConfig struct {
	Enabled           bool   `json:"enabled"`
	WebhookID         string `json:"webhook_id"`
	WebhookToken      string `json:"webhook_token"`
	GeoapifyKey       string `json:"geoapify_key"`
	CrowdSecCTIKey    string `json:"crowdsec_cti_api_key"`
	CrowdSecRestarted bool   `json:"crowdsec_restarted,omitempty"` // Status flag
	ManuallyConfigured bool  `json:"manually_configured,omitempty"` // Indicates if config was manually added by user
	ConfigSource      string `json:"config_source,omitempty"`       // Where config was found: "database", "container", "both"
}

// ConsoleStatus represents the CrowdSec Console enrollment status
type ConsoleStatus struct {
	Enrolled          bool `json:"enrolled"`
	Validated         bool `json:"validated"`
	Manual            bool `json:"manual"`
	ConsoleManagement bool `json:"console_management"`
	Context           bool `json:"context"`
	Custom            bool `json:"custom"`
	Tainted           bool `json:"tainted"`
}

// ProfileRequest represents the request to update profiles.yaml
type ProfileRequest struct {
	Content string `json:"content"`
	Restart bool   `json:"restart"`
}

// ProfileHistory represents a historical version of profiles.yaml
type ProfileHistory struct {
	ID        int       `json:"id"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}
// Proxy-related models for multi-proxy architecture

// ProxyIntegration represents proxy integration status (replaces TraefikIntegration)
type ProxyIntegration struct {
	Type                string   `json:"type"`
	BouncerConfigured   bool     `json:"bouncer_configured"`
	BouncerName         string   `json:"bouncer_name"`
	SupportedFeatures   []string `json:"supported_features"`
	ConfigFiles         []string `json:"config_files"`
	ContainerName       string   `json:"container_name"`
	Running             bool     `json:"running"`
	IntegrationType     string   `json:"integration_type,omitempty"` // plugin, module, spoa, etc.
}

// WhitelistRequest (Updated for multi-proxy support)
type WhitelistRequestV2 struct {
	IP            string `json:"ip"`
	CIDR          string `json:"cidr,omitempty"`
	AddToCrowdSec bool   `json:"add_to_crowdsec"`
	AddToTraefik  bool   `json:"add_to_traefik"`  // LEGACY - Supported forever
	AddToProxy    bool   `json:"add_to_proxy"`    // NEW - Generic field
	Comprehensive bool   `json:"comprehensive,omitempty"`
}

// IPInfo (Updated for multi-proxy support)
type IPInfoV2 struct {
	IP            string `json:"ip"`
	IsBlocked     bool   `json:"is_blocked"`
	IsWhitelisted bool   `json:"is_whitelisted"`
	InCrowdSec    bool   `json:"in_crowdsec"`
	InTraefik     bool   `json:"in_traefik"`  // LEGACY - Supported forever
	InProxy       bool   `json:"in_proxy"`    // NEW - Generic field
}

// ProxySettings represents proxy configuration stored in database
type ProxySettings struct {
	ID              int               `json:"id" db:"id"`
	ProxyType       string            `json:"proxy_type" db:"proxy_type"`
	ContainerName   string            `json:"container_name" db:"container_name"`
	ConfigPaths     map[string]string `json:"config_paths" db:"config_paths"`     // JSON field
	CustomSettings  map[string]string `json:"custom_settings" db:"custom_settings"` // JSON field
	EnabledFeatures []string          `json:"enabled_features" db:"enabled_features"` // JSON field
	CreatedAt       string            `json:"created_at" db:"created_at"`
	UpdatedAt       string            `json:"updated_at" db:"updated_at"`
}

// ProxyConfigRequest represents a request to configure proxy settings
type ProxyConfigRequest struct {
	ProxyType       string            `json:"proxy_type" binding:"required"`
	ContainerName   string            `json:"container_name" binding:"required"`
	ConfigPaths     map[string]string `json:"config_paths,omitempty"`
	CustomSettings  map[string]string `json:"custom_settings,omitempty"`
	EnabledFeatures []string          `json:"enabled_features,omitempty"`
}

// ProxyTypesResponse represents available proxy types
type ProxyTypesResponse struct {
	Types []ProxyTypeInfo `json:"types"`
}

// ProxyTypeInfo represents information about a proxy type
type ProxyTypeInfo struct {
	Type              string   `json:"type"`
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	SupportedFeatures []string `json:"supported_features"`
	Registered        bool     `json:"registered"`
	Experimental      bool     `json:"experimental,omitempty"`
}

// ProxyCurrentResponse represents current proxy information
type ProxyCurrentResponse struct {
	Type              string   `json:"type"`
	Enabled           bool     `json:"enabled"`
	ContainerName     string   `json:"container_name"`
	Running           bool     `json:"running"`
	SupportedFeatures []string `json:"supported_features"`
	ConfigFiles       []string `json:"config_files"`
	Health            string   `json:"health"`
	LastHealthCheck   string   `json:"last_health_check,omitempty"`
}

// ProxyFeaturesResponse represents supported features for current proxy
type ProxyFeaturesResponse struct {
	ProxyType         string                    `json:"proxy_type"`
	SupportedFeatures []string                  `json:"supported_features"`
	FeatureDetails    map[string]FeatureDetail  `json:"feature_details"`
}

// FeatureDetail provides detailed information about a feature
type FeatureDetail struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Available   bool   `json:"available"`
	Reason      string `json:"reason,omitempty"` // Why feature is not available
}
// Add-on related models for Traefik add-ons (Pangolin/Gerbil)

// AddonsResponse represents available add-ons for the current proxy type
type AddonsResponse struct {
	ProxyType       string      `json:"proxy_type"`
	AvailableAddons []AddonInfo `json:"available_addons"`
	TotalAddons     int         `json:"total_addons"`
	SupportedAddons int         `json:"supported_addons"`
}

// AddonInfo represents information about an add-on
type AddonInfo struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Description string   `json:"description"`
	ProxyTypes  []string `json:"proxy_types"`
	Required    bool     `json:"required"`
	Category    string   `json:"category"`
	Status      AddonStatus `json:"status"`
	Features    []string `json:"features"`
}

// AddonStatus represents the current status of an add-on
type AddonStatus struct {
	Name          string `json:"name"`
	Enabled       bool   `json:"enabled"`
	Running       bool   `json:"running"`
	ContainerName string `json:"container_name"`
	Version       string `json:"version"`
	Health        string `json:"health"`
}

// AddonConfiguration represents configuration settings for an add-on
type AddonConfiguration struct {
	Name     string                 `json:"name"`
	Settings map[string]interface{} `json:"settings"`
}

// AddonEnableRequest represents a request to enable an add-on
type AddonEnableRequest struct {
	Addon   string                 `json:"addon" binding:"required"`
	Config  map[string]interface{} `json:"config,omitempty"`
	Restart bool                   `json:"restart,omitempty"`
}

// AddonDisableRequest represents a request to disable an add-on
type AddonDisableRequest struct {
	Addon   string `json:"addon" binding:"required"`
	Restart bool   `json:"restart,omitempty"`
}