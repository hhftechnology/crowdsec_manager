package models

// NameValue is a generic chart-friendly pair used by bar/donut widgets.
type NameValue struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

// DashboardRange identifies one of the supported quick presets.
type DashboardRange string

const (
	Range5m  DashboardRange = "5m"
	Range1h  DashboardRange = "1h"
	Range6h  DashboardRange = "6h"
	Range24h DashboardRange = "24h"
)

// IPStat is a single row in the "top IPs" widget.
// Country/Lat/Lng are populated when GeoIP data is available.
type IPStat struct {
	IP      string  `json:"ip"`
	Count   int     `json:"count"`
	Country string  `json:"country,omitempty"`
	Lat     float64 `json:"lat,omitempty"`
	Lng     float64 `json:"lng,omitempty"`
}

// TraefikBucket is one point on the Traefik request volume time-series.
type TraefikBucket struct {
	T     string `json:"t"` // ISO-8601 bucket start
	Total int    `json:"total"`
	C2xx  int    `json:"c2xx"`
	C3xx  int    `json:"c3xx"`
	C4xx  int    `json:"c4xx"`
	C5xx  int    `json:"c5xx"`
}

// TraefikRecentError is a single row in the Traefik recent-errors feed.
type TraefikRecentError struct {
	T          string `json:"t"`
	IP         string `json:"ip"`
	Method     string `json:"method,omitempty"`
	Path       string `json:"path,omitempty"`
	Status     int    `json:"status"`
	DurationMs int64  `json:"duration_ms,omitempty"`
}

// TraefikDashboard is the complete payload returned by
// GET /api/logs/traefik/dashboard.
//
// AvgDurationMs is a pointer (rather than carrying omitempty) so that
// the JSON payload makes the absence explicit when Traefik is configured
// with the Common Log Format and no duration field is available.
type TraefikDashboard struct {
	Range            DashboardRange       `json:"range"`
	Format           string               `json:"format"` // "json" or "clf"
	GeneratedAt      string               `json:"generated_at"`
	TotalRequests    int                  `json:"total_requests"`
	UniqueIPs        int                  `json:"unique_ips"`
	AvgDurationMs    *float64             `json:"avg_duration_ms"`
	ErrorRate        float64              `json:"error_rate"`
	Series           []TraefikBucket      `json:"series"`
	StatusCodes      []NameValue          `json:"status_codes"`
	Methods          []NameValue          `json:"methods"`
	TopIPs           []IPStat             `json:"top_ips"`
	TopHosts         []NameValue          `json:"top_hosts"`
	TopRouters       []NameValue          `json:"top_routers"`
	SlowestEndpoints []NameValue          `json:"slowest_endpoints"` // value = ms
	TLSVersions      []NameValue          `json:"tls_versions"`
	RecentErrors     []TraefikRecentError `json:"recent_errors"`
}

// CrowdSecBucket is one point on the CrowdSec event volume time-series.
type CrowdSecBucket struct {
	T         string `json:"t"`
	Alerts    int    `json:"alerts"`
	Decisions int    `json:"decisions"`
	Errors    int    `json:"errors"`
}

// AcquisitionStat counts ingested lines per source/file.
type AcquisitionStat struct {
	Source string `json:"source"`
	Lines  int    `json:"lines"`
}

// CrowdSecActivity is a single row in the bouncer activity / recent
// errors feed.
type CrowdSecActivity struct {
	T       string `json:"t"`
	Level   string `json:"level"`
	Source  string `json:"source,omitempty"`
	Message string `json:"message"`
}

// CrowdSecDashboard is the complete payload returned by
// GET /api/logs/crowdsec/dashboard.
type CrowdSecDashboard struct {
	Range            DashboardRange     `json:"range"`
	GeneratedAt      string             `json:"generated_at"`
	TotalEvents      int                `json:"total_events"`
	Decisions        int                `json:"decisions"`
	Alerts           int                `json:"alerts"`
	ParserErrors     int                `json:"parser_errors"`
	Series           []CrowdSecBucket   `json:"series"`
	TopScenarios     []NameValue        `json:"top_scenarios"`
	TopSourceIPs     []IPStat           `json:"top_source_ips"`
	TopOrigins       []NameValue        `json:"top_origins"`
	TopDecisionTypes []NameValue        `json:"top_decision_types"`
	Acquisition      []AcquisitionStat  `json:"acquisition"`
	BouncerActivity  []CrowdSecActivity `json:"bouncer_activity"`
	RecentErrors     []CrowdSecActivity `json:"recent_errors"`
}
