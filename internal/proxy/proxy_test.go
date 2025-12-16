package proxy

import (
	"context"
	"crowdsec-manager/internal/models"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// **Feature: multi-proxy-architecture, Property 4: Plugin Architecture Extensibility**
// **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5**
func TestProxyAdapterInterfaceExtensibility(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random proxy type
		proxyType := rapid.SampledFrom([]ProxyType{
			ProxyTypeTraefik,
			ProxyTypeNginx,
			ProxyTypeCaddy,
			ProxyTypeHAProxy,
			ProxyTypeZoraxy,
			ProxyTypeStandalone,
		}).Draw(t, "proxyType")

		// Generate random configuration
		containerName := rapid.StringMatching(`^[a-zA-Z][a-zA-Z0-9_-]*$`).Draw(t, "containerName")
		
		config := &ProxyConfig{
			Type:          proxyType,
			Enabled:       rapid.Bool().Draw(t, "enabled"),
			ContainerName: containerName,
			ConfigPaths:   make(map[string]string),
			CustomSettings: make(map[string]string),
		}

		// Test that we can create an adapter for registered types
		registry := NewRegistry()
		
		// Register a mock adapter for the proxy type
		mockFactory := func() ProxyAdapter {
			return &MockAdapter{
				proxyType: proxyType,
				features:  GetSupportedFeatures(proxyType).List(),
			}
		}
		
		err := registry.Register(proxyType, mockFactory)
		if err != nil {
			t.Fatalf("Failed to register adapter: %v", err)
		}

		// Property 1: Adapter creation should succeed for registered types
		adapter, err := registry.Create(proxyType)
		if err != nil {
			t.Fatalf("Failed to create adapter for registered type %s: %v", proxyType, err)
		}

		// Property 2: Created adapter should implement the interface correctly
		if adapter.Type() != proxyType {
			t.Errorf("Adapter type mismatch: got %s, want %s", adapter.Type(), proxyType)
		}

		// Property 3: Adapter should declare supported features correctly
		supportedFeatures := adapter.SupportedFeatures()
		expectedFeatures := GetSupportedFeatures(proxyType)
		
		if len(supportedFeatures) != len(expectedFeatures.List()) {
			t.Errorf("Feature count mismatch: got %d, want %d", len(supportedFeatures), len(expectedFeatures.List()))
		}

		// Property 4: Initialization should work without errors for valid config
		ctx := context.Background()
		err = adapter.Initialize(ctx, config)
		if err != nil {
			t.Errorf("Adapter initialization failed: %v", err)
		}

		// Property 5: Health check should return valid status
		health, err := adapter.HealthCheck(ctx)
		if err != nil {
			t.Errorf("Health check failed: %v", err)
		}
		if health == nil {
			t.Error("Health check returned nil")
		}

		// Property 6: Feature managers should be consistent with supported features
		featureSet := GetSupportedFeatures(proxyType)
		
		if featureSet.Has(FeatureWhitelist) {
			if adapter.WhitelistManager() == nil {
				t.Error("WhitelistManager should not be nil for proxy type supporting whitelist")
			}
		} else {
			if adapter.WhitelistManager() != nil {
				t.Error("WhitelistManager should be nil for proxy type not supporting whitelist")
			}
		}

		if featureSet.Has(FeatureCaptcha) {
			if adapter.CaptchaManager() == nil {
				t.Error("CaptchaManager should not be nil for proxy type supporting captcha")
			}
		} else {
			if adapter.CaptchaManager() != nil {
				t.Error("CaptchaManager should be nil for proxy type not supporting captcha")
			}
		}

		if featureSet.Has(FeatureLogs) {
			if adapter.LogManager() == nil {
				t.Error("LogManager should not be nil for proxy type supporting logs")
			}
		} else {
			if adapter.LogManager() != nil {
				t.Error("LogManager should be nil for proxy type not supporting logs")
			}
		}

		if featureSet.Has(FeatureBouncer) {
			if adapter.BouncerManager() == nil {
				t.Error("BouncerManager should not be nil for proxy type supporting bouncer")
			}
		} else {
			if adapter.BouncerManager() != nil {
				t.Error("BouncerManager should be nil for proxy type not supporting bouncer")
			}
		}
	})
}

// MockAdapter implements ProxyAdapter for testing
type MockAdapter struct {
	proxyType ProxyType
	features  []Feature
	config    *ProxyConfig
}

func (m *MockAdapter) Name() string {
	return string(m.proxyType) + " Mock Adapter"
}

func (m *MockAdapter) Type() ProxyType {
	return m.proxyType
}

func (m *MockAdapter) SupportedFeatures() []Feature {
	return m.features
}

func (m *MockAdapter) Initialize(ctx context.Context, cfg *ProxyConfig) error {
	m.config = cfg
	return nil
}

func (m *MockAdapter) HealthCheck(ctx context.Context) (*models.HealthCheckItem, error) {
	return &models.HealthCheckItem{
		Status:  "healthy",
		Message: "Mock adapter is healthy",
		Metrics: map[string]interface{}{
			"proxy_type": m.proxyType,
			"timestamp":  time.Now().Unix(),
		},
	}, nil
}

func (m *MockAdapter) WhitelistManager() WhitelistManager {
	if GetSupportedFeatures(m.proxyType).Has(FeatureWhitelist) {
		return &MockWhitelistManager{}
	}
	return nil
}

func (m *MockAdapter) CaptchaManager() CaptchaManager {
	if GetSupportedFeatures(m.proxyType).Has(FeatureCaptcha) {
		return &MockCaptchaManager{}
	}
	return nil
}

func (m *MockAdapter) LogManager() LogManager {
	if GetSupportedFeatures(m.proxyType).Has(FeatureLogs) {
		return &MockLogManager{}
	}
	return nil
}

func (m *MockAdapter) BouncerManager() BouncerManager {
	if GetSupportedFeatures(m.proxyType).Has(FeatureBouncer) {
		return &MockBouncerManager{}
	}
	return nil
}

// Mock implementations of feature managers
type MockWhitelistManager struct{}

func (m *MockWhitelistManager) ViewWhitelist(ctx context.Context) ([]string, error) {
	return []string{"192.168.1.1", "10.0.0.0/8"}, nil
}

func (m *MockWhitelistManager) AddIP(ctx context.Context, ip string) error {
	return nil
}

func (m *MockWhitelistManager) RemoveIP(ctx context.Context, ip string) error {
	return nil
}

func (m *MockWhitelistManager) AddCIDR(ctx context.Context, cidr string) error {
	return nil
}

func (m *MockWhitelistManager) RemoveCIDR(ctx context.Context, cidr string) error {
	return nil
}

type MockCaptchaManager struct{}

func (m *MockCaptchaManager) SetupCaptcha(ctx context.Context, req *models.CaptchaSetupRequest) error {
	return nil
}

func (m *MockCaptchaManager) GetCaptchaStatus(ctx context.Context) (*CaptchaStatus, error) {
	return &CaptchaStatus{
		Enabled:  true,
		Provider: "cloudflare",
		SiteKey:  "mock-site-key",
	}, nil
}

func (m *MockCaptchaManager) DisableCaptcha(ctx context.Context) error {
	return nil
}

type MockLogManager struct{}

func (m *MockLogManager) GetAccessLogs(ctx context.Context, tail int) (string, error) {
	return "mock log entries", nil
}

func (m *MockLogManager) AnalyzeLogs(ctx context.Context, tail int) (*models.LogStats, error) {
	return &models.LogStats{
		TotalLines:  100,
		StatusCodes: map[string]int{"200": 80, "404": 20},
	}, nil
}

func (m *MockLogManager) GetLogPath() string {
	return "/var/log/mock.log"
}

type MockBouncerManager struct{}

func (m *MockBouncerManager) IsBouncerConfigured(ctx context.Context) (bool, error) {
	return true, nil
}

func (m *MockBouncerManager) GetBouncerStatus(ctx context.Context) (*BouncerStatus, error) {
	return &BouncerStatus{
		Configured:      true,
		Connected:       true,
		BouncerName:     "mock-bouncer",
		IntegrationType: "mock",
	}, nil
}

func (m *MockBouncerManager) ValidateConfiguration(ctx context.Context) error {
	return nil
}