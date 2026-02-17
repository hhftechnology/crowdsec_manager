package caddy

import (
	"context"

	"github.com/crowdsecurity/crowdsec-manager/internal/proxy"
)

// CaddyAdapter is a skeleton adapter for Caddy reverse proxy.
type CaddyAdapter struct{}

func NewCaddyAdapter() *CaddyAdapter { return &CaddyAdapter{} }

func (a *CaddyAdapter) Name() string                             { return "Caddy" }
func (a *CaddyAdapter) Type() proxy.ProxyType                    { return proxy.ProxyCaddy }
func (a *CaddyAdapter) SupportedFeatures() []proxy.Feature       { return []proxy.Feature{proxy.FeatureHealth} }
func (a *CaddyAdapter) Initialize(_ context.Context, _ proxy.InitConfig) error { return nil }

func (a *CaddyAdapter) HealthCheck(_ context.Context) (*proxy.HealthResult, error) {
	return &proxy.HealthResult{Healthy: false, Message: "caddy adapter not fully implemented"}, nil
}

func (a *CaddyAdapter) WhitelistManager() proxy.WhitelistManager { return &noop{} }
func (a *CaddyAdapter) CaptchaManager() proxy.CaptchaManager     { return &noopC{} }
func (a *CaddyAdapter) LogManager() proxy.LogManager              { return &noopL{} }
func (a *CaddyAdapter) BouncerManager() proxy.BouncerManager      { return &noopB{} }

type noop struct{}
func (n *noop) List(_ context.Context) ([]proxy.WhitelistEntry, error) { return nil, nil }
func (n *noop) Add(_ context.Context, _ proxy.WhitelistEntry) error    { return nil }
func (n *noop) Remove(_ context.Context, _ string) error               { return nil }

type noopC struct{}
func (n *noopC) Status(_ context.Context) (*proxy.CaptchaStatus, error) { return &proxy.CaptchaStatus{}, nil }
func (n *noopC) Setup(_ context.Context, _ proxy.CaptchaConfig) error   { return nil }
func (n *noopC) Disable(_ context.Context) error                        { return nil }

type noopL struct{}
func (n *noopL) GetLogs(_ context.Context, _ proxy.LogOptions) ([]proxy.LogEntry, error) { return nil, nil }
func (n *noopL) StreamLogs(_ context.Context, _ proxy.LogOptions) (<-chan proxy.LogEntry, error) { return nil, nil }

type noopB struct{}
func (n *noopB) Status(_ context.Context) (*proxy.BouncerStatus, error) { return &proxy.BouncerStatus{}, nil }
func (n *noopB) List(_ context.Context) ([]proxy.BouncerInfo, error)    { return nil, nil }
