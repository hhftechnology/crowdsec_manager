package standalone

import (
	"context"

	"github.com/crowdsecurity/crowdsec-manager/internal/proxy"
)

// StandaloneAdapter is a minimal adapter for deployments without a proxy.
type StandaloneAdapter struct{}

func NewStandaloneAdapter() *StandaloneAdapter { return &StandaloneAdapter{} }

func (a *StandaloneAdapter) Name() string                             { return "Standalone" }
func (a *StandaloneAdapter) Type() proxy.ProxyType                    { return proxy.ProxyStandalone }
func (a *StandaloneAdapter) SupportedFeatures() []proxy.Feature       { return []proxy.Feature{proxy.FeatureHealth} }
func (a *StandaloneAdapter) Initialize(_ context.Context, _ proxy.InitConfig) error { return nil }

func (a *StandaloneAdapter) HealthCheck(_ context.Context) (*proxy.HealthResult, error) {
	return &proxy.HealthResult{Healthy: true, Message: "standalone mode"}, nil
}

func (a *StandaloneAdapter) WhitelistManager() proxy.WhitelistManager { return &noopWhitelist{} }
func (a *StandaloneAdapter) CaptchaManager() proxy.CaptchaManager     { return &noopCaptcha{} }
func (a *StandaloneAdapter) LogManager() proxy.LogManager              { return &noopLogs{} }
func (a *StandaloneAdapter) BouncerManager() proxy.BouncerManager      { return &noopBouncer{} }

// Noop implementations for unsupported features.

type noopWhitelist struct{}
func (n *noopWhitelist) List(_ context.Context) ([]proxy.WhitelistEntry, error)      { return nil, nil }
func (n *noopWhitelist) Add(_ context.Context, _ proxy.WhitelistEntry) error          { return nil }
func (n *noopWhitelist) Remove(_ context.Context, _ string) error                     { return nil }

type noopCaptcha struct{}
func (n *noopCaptcha) Status(_ context.Context) (*proxy.CaptchaStatus, error) { return &proxy.CaptchaStatus{}, nil }
func (n *noopCaptcha) Setup(_ context.Context, _ proxy.CaptchaConfig) error   { return nil }
func (n *noopCaptcha) Disable(_ context.Context) error                        { return nil }

type noopLogs struct{}
func (n *noopLogs) GetLogs(_ context.Context, _ proxy.LogOptions) ([]proxy.LogEntry, error) { return nil, nil }
func (n *noopLogs) StreamLogs(_ context.Context, _ proxy.LogOptions) (<-chan proxy.LogEntry, error) { return nil, nil }

type noopBouncer struct{}
func (n *noopBouncer) Status(_ context.Context) (*proxy.BouncerStatus, error) { return &proxy.BouncerStatus{}, nil }
func (n *noopBouncer) List(_ context.Context) ([]proxy.BouncerInfo, error)    { return nil, nil }
