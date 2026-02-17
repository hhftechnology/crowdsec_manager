package proxy

import (
	"context"

	"github.com/crowdsecurity/crowdsec-manager/internal/config"
	"github.com/crowdsecurity/crowdsec-manager/internal/database"
	"github.com/crowdsecurity/crowdsec-manager/internal/docker"
)

// InitConfig is the concrete configuration passed during adapter initialization.
type InitConfig struct {
	Docker *docker.Client
	Config *config.Config
	DB     *database.Database
}

// ProxyAdapter is the core interface every proxy type must implement.
type ProxyAdapter interface {
	Name() string
	Type() ProxyType
	SupportedFeatures() []Feature
	Initialize(ctx context.Context, cfg InitConfig) error
	HealthCheck(ctx context.Context) (*HealthResult, error)
	WhitelistManager() WhitelistManager
	CaptchaManager() CaptchaManager
	LogManager() LogManager
	BouncerManager() BouncerManager
}

// WhitelistManager handles proxy-level IP whitelisting.
type WhitelistManager interface {
	List(ctx context.Context) ([]WhitelistEntry, error)
	Add(ctx context.Context, entry WhitelistEntry) error
	Remove(ctx context.Context, ip string) error
}

// CaptchaManager handles captcha challenge configuration.
type CaptchaManager interface {
	Status(ctx context.Context) (*CaptchaStatus, error)
	Setup(ctx context.Context, cfg CaptchaConfig) error
	Disable(ctx context.Context) error
}

// LogManager handles log retrieval from the proxy.
type LogManager interface {
	GetLogs(ctx context.Context, opts LogOptions) ([]LogEntry, error)
	StreamLogs(ctx context.Context, opts LogOptions) (<-chan LogEntry, error)
}

// BouncerManager handles bouncer status queries.
type BouncerManager interface {
	Status(ctx context.Context) (*BouncerStatus, error)
	List(ctx context.Context) ([]BouncerInfo, error)
}
