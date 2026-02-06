package proxy

import (
	"context"
	"testing"

	"crowdsec-manager/internal/models"
)

// mockAdapter implements ProxyAdapter for testing nil-safe helpers.
type mockAdapter struct {
	proxyType        ProxyType
	features         []Feature
	whitelistMgr     WhitelistManager
	captchaMgr       CaptchaManager
	logMgr           LogManager
	bouncerMgr       BouncerManager
}

func (m *mockAdapter) Name() string                        { return string(m.proxyType) }
func (m *mockAdapter) Type() ProxyType                     { return m.proxyType }
func (m *mockAdapter) Initialize(context.Context, *ProxyConfig) error { return nil }
func (m *mockAdapter) SupportedFeatures() []Feature        { return m.features }
func (m *mockAdapter) HealthCheck(context.Context) (*models.HealthCheckItem, error) { return nil, nil }
func (m *mockAdapter) WhitelistManager() WhitelistManager  { return m.whitelistMgr }
func (m *mockAdapter) CaptchaManager() CaptchaManager      { return m.captchaMgr }
func (m *mockAdapter) LogManager() LogManager              { return m.logMgr }
func (m *mockAdapter) BouncerManager() BouncerManager      { return m.bouncerMgr }

func TestRequireWhitelist(t *testing.T) {
	// Adapter without whitelist
	adapter := &mockAdapter{proxyType: ProxyTypeStandalone}
	_, err := RequireWhitelist(adapter)
	if err == nil {
		t.Error("expected error for nil whitelist manager")
	}
}

func TestRequireCaptcha(t *testing.T) {
	adapter := &mockAdapter{proxyType: ProxyTypeNginx}
	_, err := RequireCaptcha(adapter)
	if err == nil {
		t.Error("expected error for nil captcha manager")
	}
}

func TestRequireLogs(t *testing.T) {
	adapter := &mockAdapter{proxyType: ProxyTypeStandalone}
	_, err := RequireLogs(adapter)
	if err == nil {
		t.Error("expected error for nil log manager")
	}
}

func TestRequireBouncer(t *testing.T) {
	adapter := &mockAdapter{proxyType: ProxyTypeZoraxy}
	_, err := RequireBouncer(adapter)
	if err == nil {
		t.Error("expected error for nil bouncer manager")
	}
}
