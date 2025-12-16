package proxy

import (
	"context"
	"crowdsec-manager/internal/models"
)

// ProxyType represents the type of reverse proxy
type ProxyType string

const (
	ProxyTypeTraefik    ProxyType = "traefik"
	ProxyTypeNginx      ProxyType = "nginx"
	ProxyTypeCaddy      ProxyType = "caddy"
	ProxyTypeHAProxy    ProxyType = "haproxy"
	ProxyTypeZoraxy     ProxyType = "zoraxy"
	ProxyTypeStandalone ProxyType = "standalone"
)

// Feature represents a proxy feature capability
type Feature string

const (
	FeatureWhitelist Feature = "whitelist"
	FeatureCaptcha   Feature = "captcha"
	FeatureLogs      Feature = "logs"
	FeatureBouncer   Feature = "bouncer"
	FeatureHealth    Feature = "health"
	FeatureAppSec    Feature = "appsec"
)

// ProxyAdapter defines the interface that all proxy adapters must implement
type ProxyAdapter interface {
	// Metadata
	Name() string
	Type() ProxyType
	SupportedFeatures() []Feature
	
	// Lifecycle
	Initialize(ctx context.Context, cfg *ProxyConfig) error
	HealthCheck(ctx context.Context) (*models.HealthCheckItem, error)
	
	// Feature managers (return nil if not supported)
	WhitelistManager() WhitelistManager
	CaptchaManager() CaptchaManager
	LogManager() LogManager
	BouncerManager() BouncerManager
}

// WhitelistManager handles proxy-level IP whitelisting
type WhitelistManager interface {
	ViewWhitelist(ctx context.Context) ([]string, error)
	AddIP(ctx context.Context, ip string) error
	RemoveIP(ctx context.Context, ip string) error
	AddCIDR(ctx context.Context, cidr string) error
	RemoveCIDR(ctx context.Context, cidr string) error
}

// CaptchaManager handles proxy-level captcha configuration
type CaptchaManager interface {
	SetupCaptcha(ctx context.Context, req *models.CaptchaSetupRequest) error
	GetCaptchaStatus(ctx context.Context) (*CaptchaStatus, error)
	DisableCaptcha(ctx context.Context) error
}

// LogManager handles proxy access log parsing and analysis
type LogManager interface {
	GetAccessLogs(ctx context.Context, tail int) (string, error)
	AnalyzeLogs(ctx context.Context, tail int) (*models.LogStats, error)
	GetLogPath() string
}

// BouncerManager handles bouncer integration status and configuration
type BouncerManager interface {
	IsBouncerConfigured(ctx context.Context) (bool, error)
	GetBouncerStatus(ctx context.Context) (*BouncerStatus, error)
	ValidateConfiguration(ctx context.Context) error
}

// ProxyConfig holds configuration for a proxy adapter
type ProxyConfig struct {
	Type            ProxyType
	Enabled         bool
	ContainerName   string
	ConfigPaths     map[string]string  // dynamic, static, logs, etc.
	CustomSettings  map[string]string  // proxy-specific settings
	DockerClient    interface{}        // Docker client interface
}

// ProxyInfo provides information about the current proxy configuration
type ProxyInfo struct {
	Type              string   `json:"type"`
	Enabled           bool     `json:"enabled"`
	ContainerName     string   `json:"container_name"`
	Running           bool     `json:"running"`
	SupportedFeatures []string `json:"supported_features"`
	ConfigFiles       []string `json:"config_files"`
}

// CaptchaStatus represents the current captcha configuration status
type CaptchaStatus struct {
	Enabled         bool   `json:"enabled"`
	Provider        string `json:"provider"`
	SiteKey         string `json:"site_key"`
	ConfiguredAt    string `json:"configured_at,omitempty"`
	LastValidation  string `json:"last_validation,omitempty"`
	ValidationError string `json:"validation_error,omitempty"`
}

// BouncerStatus represents the current bouncer integration status
type BouncerStatus struct {
	Configured      bool   `json:"configured"`
	Connected       bool   `json:"connected"`
	BouncerName     string `json:"bouncer_name"`
	Version         string `json:"version,omitempty"`
	LastSeen        string `json:"last_seen,omitempty"`
	ConfigPath      string `json:"config_path,omitempty"`
	IntegrationType string `json:"integration_type"` // plugin, module, spoa, etc.
	Error           string `json:"error,omitempty"`
}