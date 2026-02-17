package nginx

import (
	"context"

	"github.com/crowdsecurity/crowdsec-manager/internal/proxy"
)

// NginxAdapter is a skeleton adapter for Nginx reverse proxy.
type NginxAdapter struct{}

func NewNginxAdapter() *NginxAdapter { return &NginxAdapter{} }

func (a *NginxAdapter) Name() string                             { return "Nginx" }
func (a *NginxAdapter) Type() proxy.ProxyType                    { return proxy.ProxyNginx }
func (a *NginxAdapter) SupportedFeatures() []proxy.Feature       { return []proxy.Feature{proxy.FeatureHealth} }
func (a *NginxAdapter) Initialize(_ context.Context, _ proxy.InitConfig) error { return nil }

func (a *NginxAdapter) HealthCheck(_ context.Context) (*proxy.HealthResult, error) {
	return &proxy.HealthResult{Healthy: false, Message: "nginx adapter not fully implemented"}, nil
}

func (a *NginxAdapter) WhitelistManager() proxy.WhitelistManager { return &noop{} }
func (a *NginxAdapter) CaptchaManager() proxy.CaptchaManager     { return &noopC{} }
func (a *NginxAdapter) LogManager() proxy.LogManager              { return &noopL{} }
func (a *NginxAdapter) BouncerManager() proxy.BouncerManager      { return &noopB{} }

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
