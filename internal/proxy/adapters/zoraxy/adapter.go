package zoraxy

import (
	"context"

	"github.com/crowdsecurity/crowdsec-manager/internal/proxy"
)

// ZoraxyAdapter is a skeleton adapter for Zoraxy reverse proxy.
type ZoraxyAdapter struct{}

func NewZoraxyAdapter() *ZoraxyAdapter { return &ZoraxyAdapter{} }

func (a *ZoraxyAdapter) Name() string                             { return "Zoraxy" }
func (a *ZoraxyAdapter) Type() proxy.ProxyType                    { return proxy.ProxyZoraxy }
func (a *ZoraxyAdapter) SupportedFeatures() []proxy.Feature       { return []proxy.Feature{proxy.FeatureHealth} }
func (a *ZoraxyAdapter) Initialize(_ context.Context, _ proxy.InitConfig) error { return nil }

func (a *ZoraxyAdapter) HealthCheck(_ context.Context) (*proxy.HealthResult, error) {
	return &proxy.HealthResult{Healthy: false, Message: "zoraxy adapter not fully implemented"}, nil
}

func (a *ZoraxyAdapter) WhitelistManager() proxy.WhitelistManager { return &noop{} }
func (a *ZoraxyAdapter) CaptchaManager() proxy.CaptchaManager     { return &noopC{} }
func (a *ZoraxyAdapter) LogManager() proxy.LogManager              { return &noopL{} }
func (a *ZoraxyAdapter) BouncerManager() proxy.BouncerManager      { return &noopB{} }

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
