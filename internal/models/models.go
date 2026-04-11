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
	AlertID   int64  `json:"alert_id"`   // ID of the parent alert
	Origin    string `json:"origin"`     // Source of the decision (crowdsec, cscli, etc.)
	Type      string `json:"type"`       // Decision type (ban, captcha, etc.)
	Scope     string `json:"scope"`      // Scope (Ip, Range, etc.)
	Value     string `json:"value"`      // IP address or range
	Duration  string `json:"duration"`   // Duration like "3h45m3s"
	Scenario  string `json:"scenario"`   // Scenario name
	Simulated bool   `json:"simulated"`  // Whether decision is simulated
	CreatedAt string `json:"created_at"` // Creation timestamp

	// Legacy/additional fields for backward compatibility
	Source string `json:"source,omitempty"` // Alias for Origin (backward compat)
	Reason string `json:"reason,omitempty"` // Alias for Scenario (some versions use this)
	Until  string `json:"until,omitempty"`  // Expiration timestamp
	UUID   string `json:"uuid,omitempty"`   // Unique identifier
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
	Valid     bool      `json:"valid"`
	LastPull  time.Time `json:"last_pull"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Type      string    `json:"type"`
	Version   string    `json:"version"`
	Status    string    `json:"status"`
}

// LastActivity returns the best-known last activity time for this bouncer.
// It prefers LastPull; falls back to UpdatedAt only when LastPull is zero
// and UpdatedAt meaningfully exceeds CreatedAt (both must be non-zero).
func (b Bouncer) LastActivity() time.Time {
	if !b.LastPull.IsZero() {
		return b.LastPull
	}
	if !b.CreatedAt.IsZero() && !b.UpdatedAt.IsZero() &&
		b.UpdatedAt.After(b.CreatedAt.Add(5*time.Second)) {
		return b.UpdatedAt
	}
	return time.Time{}
}

// LogEntry represents a log entry
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Service   string    `json:"service"`
	Message   string    `json:"message"`
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

// Metric represents a Prometheus metric
type Metric struct {
	Name   string            `json:"name"`
	Value  float64           `json:"value"`
	Labels map[string]string `json:"labels,omitempty"`
}

// DiagnosticResult represents complete diagnostic results
type DiagnosticResult struct {
	Health    *HealthStatus `json:"health"`
	Bouncers  []Bouncer     `json:"bouncers"`
	Decisions []Decision    `json:"decisions"`
	Timestamp time.Time     `json:"timestamp"`
}

// ServiceAction represents a service action (start/stop/restart)
type ServiceAction struct {
	Service string `json:"service" binding:"required"`
	Action  string `json:"action" binding:"required"` // start, stop, restart
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
	Items       []AllowlistEntry `json:"items"`           // CrowdSec uses "items", not "entries"
	CreatedAt   string           `json:"created_at"`      // When the allowlist was created
	UpdatedAt   string           `json:"updated_at"`      // When the allowlist was last updated
	Count       int              `json:"count,omitempty"` // Number of items
}

// ConsoleStatus represents the CrowdSec Console enrollment status
type ConsoleStatus struct {
	Enrolled          bool   `json:"enrolled"`
	Validated         bool   `json:"validated"`
	Manual            bool   `json:"manual"`
	ConsoleManagement bool   `json:"console_management"`
	Approved          bool   `json:"approved"`
	ManagementEnabled bool   `json:"management_enabled"`
	Phase             string `json:"phase"`
	Context           bool   `json:"context"`
	Custom            bool   `json:"custom"`
	Tainted           bool   `json:"tainted"`
}

// HubItem represents a CrowdSec hub item (scenario, parser, collection, or postoverflow)
type HubItem struct {
	Name         string `json:"name"`
	Status       string `json:"status"`
	Version      string `json:"version"`
	LocalVersion string `json:"local_version,omitempty"`
	LocalPath    string `json:"local_path,omitempty"`
	Description  string `json:"description,omitempty"`
	Author       string `json:"author,omitempty"`
}

// HubActionRequest represents a request to install or remove a hub item
type HubActionRequest struct {
	Name string `json:"name" binding:"required"`
	Type string `json:"type" binding:"required"` // scenarios, parsers, collections, postoverflows
}

// HubCategoryActionRequest represents a category-aware hub action request.
type HubCategoryActionRequest struct {
	ItemName string `json:"item_name" binding:"required"`
}

// HubManualApplyRequest writes YAML directly into the CrowdSec container.
type HubManualApplyRequest struct {
	Filename   string `json:"filename" binding:"required"`
	YAML       string `json:"yaml" binding:"required"`
	TargetPath string `json:"target_path,omitempty"`
}

// HubPreference stores per-category defaults for hub operations.
type HubPreference struct {
	Category        string `json:"category"`
	DefaultMode     string `json:"default_mode"`
	DefaultYAMLPath string `json:"default_yaml_path,omitempty"`
	LastItemName    string `json:"last_item_name,omitempty"`
	UpdatedAt       string `json:"updated_at,omitempty"`
}

// HubOperationRecord stores auditable operation history.
type HubOperationRecord struct {
	ID          int64  `json:"id"`
	Category    string `json:"category"`
	Mode        string `json:"mode"`
	Action      string `json:"action"`
	ItemName    string `json:"item_name,omitempty"`
	YAMLPath    string `json:"yaml_path,omitempty"`
	YAMLContent string `json:"yaml_content,omitempty"`
	Command     string `json:"command,omitempty"`
	Success     bool   `json:"success"`
	Output      string `json:"output,omitempty"`
	Error       string `json:"error,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

// HubOperationFilter narrows history queries.
type HubOperationFilter struct {
	Category string
	Mode     string
	Success  *bool
	Limit    int
	Offset   int
}

// SimulationRequest represents a request to enable or disable simulation for a scenario
type SimulationRequest struct {
	Scenario string `json:"scenario" binding:"required"`
	Enabled  bool   `json:"enabled"`
}

// HistoryConfig stores retention settings for CrowdSec history data.
type HistoryConfig struct {
	RetentionDays int    `json:"retention_days"`
	UpdatedAt     string `json:"updated_at,omitempty"`
}

// DecisionHistoryFilter narrows decision history queries.
type DecisionHistoryFilter struct {
	Stale    *bool
	Value    string
	Scenario string
	Since    string
	Limit    int
	Offset   int
}

// AlertHistoryFilter narrows alert history queries.
type AlertHistoryFilter struct {
	Stale    *bool
	Value    string
	Scenario string
	Since    string
	Limit    int
	Offset   int
}

// DecisionHistoryRecord is a persisted decision snapshot entry.
type DecisionHistoryRecord struct {
	ID             int64  `json:"id"`
	DedupeKey      string `json:"dedupe_key"`
	DecisionID     int64  `json:"decision_id"`
	AlertID        int64  `json:"alert_id"`
	Origin         string `json:"origin"`
	Type           string `json:"type"`
	Scope          string `json:"scope"`
	Value          string `json:"value"`
	Duration       string `json:"duration"`
	Scenario       string `json:"scenario"`
	CreatedAt      string `json:"created_at"`
	Until          string `json:"until,omitempty"`
	IsStale        bool   `json:"is_stale"`
	FirstSeenAt    string `json:"first_seen_at"`
	LastSeenAt     string `json:"last_seen_at"`
	StaleAt        string `json:"stale_at,omitempty"`
	LastSnapshotAt string `json:"last_snapshot_at"`
}

// AlertHistoryRecord is a persisted alert snapshot entry.
type AlertHistoryRecord struct {
	ID             int64  `json:"id"`
	DedupeKey      string `json:"dedupe_key"`
	AlertID        int64  `json:"alert_id"`
	Scenario       string `json:"scenario"`
	Scope          string `json:"scope"`
	Value          string `json:"value"`
	Origin         string `json:"origin"`
	Type           string `json:"type,omitempty"`
	EventsCount    int    `json:"events_count,omitempty"`
	StartAt        string `json:"start_at,omitempty"`
	StopAt         string `json:"stop_at,omitempty"`
	IsStale        bool   `json:"is_stale"`
	FirstSeenAt    string `json:"first_seen_at"`
	LastSeenAt     string `json:"last_seen_at"`
	StaleAt        string `json:"stale_at,omitempty"`
	LastSnapshotAt string `json:"last_snapshot_at"`
}

// RepeatedOffender captures repeated offender statistics.
type RepeatedOffender struct {
	Value           string `json:"value"`
	Scope           string `json:"scope"`
	HitCount        int    `json:"hit_count"`
	WindowDays      int    `json:"window_days"`
	FirstDecisionAt string `json:"first_decision_at"`
	LastDecisionAt  string `json:"last_decision_at"`
	LastNotifiedAt  string `json:"last_notified_at,omitempty"`
}

// HistoryStats provides aggregate counts for the history dashboard.
type HistoryStats struct {
	TotalDecisions        int `json:"total_decisions"`
	ActiveDecisions       int `json:"active_decisions"`
	TotalAlerts           int `json:"total_alerts"`
	ActiveAlerts          int `json:"active_alerts"`
	RepeatedOffenderCount int `json:"repeated_offender_count"`
}

// ReapplyDecisionRequest re-inserts a historical decision into CrowdSec.
type ReapplyDecisionRequest struct {
	ID       int64  `json:"id"`
	Type     string `json:"type"`     // "ban" | "captcha"
	Duration string `json:"duration"` // e.g. "24h", "7d"
	Reason   string `json:"reason,omitempty"`
}

// BulkReapplyDecisionsRequest re-inserts multiple historical decisions.
type BulkReapplyDecisionsRequest struct {
	IDs      []int64 `json:"ids"`
	Type     string  `json:"type"`
	Duration string  `json:"duration"`
	Reason   string  `json:"reason,omitempty"`
}

// BulkReapplyResult reports outcomes of a bulk re-apply operation.
type BulkReapplyResult struct {
	Succeeded int      `json:"succeeded"`
	Failed    int      `json:"failed"`
	Errors    []string `json:"errors,omitempty"`
}
