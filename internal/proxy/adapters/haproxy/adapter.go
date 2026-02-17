package haproxy

import (
	"context"

	"github.com/crowdsecurity/crowdsec-manager/internal/proxy"
)

// HAProxyAdapter is a skeleton adapter for HAProxy.
type HAProxyAdapter struct{}

func NewHAProxyAdapter() *HAProxyAdapter { return &HAProxyAdapter{} }

func (a *HAProxyAdapter) Name() string                             { return "HAProxy" }
func (a *HAProxyAdapter) Type() proxy.ProxyType                    { return proxy.ProxyHAProxy }
func (a *HAProxyAdapter) SupportedFeatures() []proxy.Feature       { return []proxy.Feature{proxy.FeatureHealth} }
func (a *HAProxyAdapter) Initialize(_ context.Context, _ proxy.InitConfig) error { return nil }

func (a *HAProxyAdapter) HealthCheck(_ context.Context) (*proxy.HealthResult, error) {
	return &proxy.HealthResult{Healthy: false, Message: "haproxy adapter not fully implemented"}, nil
}

func (a *HAProxyAdapter) WhitelistManager() proxy.WhitelistManager { return &noop{} }
func (a *HAProxyAdapter) CaptchaManager() proxy.CaptchaManager     { return &noopC{} }
func (a *HAProxyAdapter) LogManager() proxy.LogManager              { return &noopL{} }
func (a *HAProxyAdapter) BouncerManager() proxy.BouncerManager      { return &noopB{} }

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
