package proxy

// ProxyType identifies a supported reverse proxy.
type ProxyType string

const (
	ProxyTraefik    ProxyType = "traefik"
	ProxyNginx      ProxyType = "nginx"
	ProxyCaddy      ProxyType = "caddy"
	ProxyHAProxy    ProxyType = "haproxy"
	ProxyZoraxy     ProxyType = "zoraxy"
	ProxyStandalone ProxyType = "standalone"
)

// Feature identifies a capability that a proxy adapter may support.
type Feature string

const (
	FeatureWhitelist Feature = "whitelist"
	FeatureCaptcha   Feature = "captcha"
	FeatureLogs      Feature = "logs"
	FeatureBouncer   Feature = "bouncer"
	FeatureHealth    Feature = "health"
)

// AdapterConfig is passed to each adapter during initialization.
type AdapterConfig struct {
	Docker interface{ /* *docker.Client — avoids circular import */ }
	Config interface{ /* *config.Config */ }
	DB     interface{ /* *database.Database */ }
}

// HealthResult reports the outcome of a health check.
type HealthResult struct {
	Healthy bool   `json:"healthy"`
	Message string `json:"message"`
}

// WhitelistEntry represents a single whitelisted IP address.
type WhitelistEntry struct {
	IP      string `json:"ip"`
	Source  string `json:"source"`
	AddedAt string `json:"added_at"`
	Reason  string `json:"reason,omitempty"`
}

// CaptchaConfig holds the configuration for captcha setup.
type CaptchaConfig struct {
	Provider  string `json:"provider"`
	SiteKey   string `json:"site_key"`
	SecretKey string `json:"secret_key"`
	Enabled   bool   `json:"enabled"`
}

// CaptchaStatus reports the current state of captcha configuration.
type CaptchaStatus struct {
	Enabled    bool   `json:"enabled"`
	Provider   string `json:"provider,omitempty"`
	SiteKey    string `json:"site_key,omitempty"`
	HTMLExists bool   `json:"html_exists"`
	ConfigOK   bool   `json:"config_ok"`
}

// LogEntry is a single parsed log line.
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Source    string `json:"source,omitempty"`
}

// LogOptions controls log retrieval.
type LogOptions struct {
	Service string
	Lines   int
	Follow  bool
}

// BouncerInfo describes a registered CrowdSec bouncer.
type BouncerInfo struct {
	Name      string `json:"name"`
	IPAddress string `json:"ip_address"`
	Type      string `json:"type"`
	LastPull  string `json:"last_pull"`
	Valid     bool   `json:"valid"`
}

// BouncerStatus is the aggregated bouncer state.
type BouncerStatus struct {
	Bouncers []BouncerInfo `json:"bouncers"`
	Count    int           `json:"count"`
}
