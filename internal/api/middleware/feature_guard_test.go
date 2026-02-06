package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/proxy"

	"github.com/gin-gonic/gin"
)

// mockProxyAdapter implements proxy.ProxyAdapter for testing.
type mockProxyAdapter struct {
	proxyType proxy.ProxyType
}

func (m *mockProxyAdapter) Name() string                                           { return string(m.proxyType) }
func (m *mockProxyAdapter) Type() proxy.ProxyType                                  { return m.proxyType }
func (m *mockProxyAdapter) Initialize(context.Context, *proxy.ProxyConfig) error   { return nil }
func (m *mockProxyAdapter) SupportedFeatures() []proxy.Feature                     { return nil }
func (m *mockProxyAdapter) HealthCheck(context.Context) (*models.HealthCheckItem, error) { return nil, nil }
func (m *mockProxyAdapter) WhitelistManager() proxy.WhitelistManager               { return nil }
func (m *mockProxyAdapter) CaptchaManager() proxy.CaptchaManager                   { return nil }
func (m *mockProxyAdapter) LogManager() proxy.LogManager                           { return nil }
func (m *mockProxyAdapter) BouncerManager() proxy.BouncerManager                   { return nil }

func TestRequireFeature_Allowed(t *testing.T) {
	gin.SetMode(gin.TestMode)

	adapter := &mockProxyAdapter{proxyType: proxy.ProxyTypeTraefik}

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.GET("/test",
		RequireFeature(adapter, proxy.FeatureWhitelist),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		},
	)

	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, c.Request)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestRequireFeature_Blocked(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Standalone adapter does not support whitelist
	adapter := &mockProxyAdapter{proxyType: proxy.ProxyTypeStandalone}

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	handlerCalled := false
	r.GET("/test",
		RequireFeature(adapter, proxy.FeatureWhitelist),
		func(c *gin.Context) {
			handlerCalled = true
			c.JSON(http.StatusOK, gin.H{"ok": true})
		},
	)

	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, c.Request)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	if handlerCalled {
		t.Error("handler should not have been called when feature is unsupported")
	}

	// Verify response body has error
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response body: %v", err)
	}
	if body["success"] != false {
		t.Error("expected success to be false")
	}
	if body["error"] == nil || body["error"] == "" {
		t.Error("expected error message in response")
	}
}
