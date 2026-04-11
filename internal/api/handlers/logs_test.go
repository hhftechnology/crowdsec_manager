package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"

	"github.com/gin-gonic/gin"
)

// ---- resolveCrowdsecLogService tests ----

// newTestConfig creates a minimal Config for testing log service resolution.
func newTestConfig(crowdsecName string) *config.Config {
	return &config.Config{
		CrowdsecContainerName: crowdsecName,
	}
}

func TestResolveCrowdsecLogService_CrowdsecKeyword(t *testing.T) {
	cfg := newTestConfig("crowdsec")

	containerName, ok := resolveCrowdsecLogService("crowdsec", cfg)
	if !ok {
		t.Fatal("expected ok=true for 'crowdsec' service param")
	}
	if containerName != "crowdsec" {
		t.Errorf("containerName: got %q, want %q", containerName, "crowdsec")
	}
}

func TestResolveCrowdsecLogService_ByContainerName(t *testing.T) {
	cfg := newTestConfig("my-crowdsec")

	containerName, ok := resolveCrowdsecLogService("my-crowdsec", cfg)
	if !ok {
		t.Fatal("expected ok=true when matching container name")
	}
	if containerName != "my-crowdsec" {
		t.Errorf("containerName: got %q, want %q", containerName, "my-crowdsec")
	}
}

func TestResolveCrowdsecLogService_UnsupportedService(t *testing.T) {
	cfg := newTestConfig("crowdsec")

	tests := []string{"traefik", "pangolin", "gerbil", "nginx", ""}

	for _, svc := range tests {
		t.Run("service="+svc, func(t *testing.T) {
			containerName, ok := resolveCrowdsecLogService(svc, cfg)
			if ok {
				t.Errorf("expected ok=false for unsupported service %q, got containerName=%q", svc, containerName)
			}
			if containerName != "" {
				t.Errorf("expected empty containerName for unsupported service, got %q", containerName)
			}
		})
	}
}

func TestResolveCrowdsecLogService_CustomContainerName(t *testing.T) {
	// The function must match the exact CrowdsecContainerName from config
	cfg := newTestConfig("custom-crowdsec-instance")

	// "crowdsec" keyword always matches
	_, ok := resolveCrowdsecLogService("crowdsec", cfg)
	if !ok {
		t.Error("'crowdsec' keyword should always resolve successfully")
	}

	// Exact custom name matches
	_, ok = resolveCrowdsecLogService("custom-crowdsec-instance", cfg)
	if !ok {
		t.Error("exact container name should resolve successfully")
	}

	// Other names don't match
	_, ok = resolveCrowdsecLogService("crowdsec-other", cfg)
	if ok {
		t.Error("non-matching name should not resolve")
	}
}

func TestStreamLogs_InvalidServiceWebSocketUpgradeReturnsPlainText(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := newTestConfig("crowdsec")
	router := gin.New()
	router.GET("/logs/stream/:service", StreamLogs(&docker.Client{}, cfg))

	req := httptest.NewRequest(http.MethodGet, "/logs/stream/not-crowdsec", nil)
	req.Header.Set("Upgrade", "websocket")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), "Only crowdsec logs are supported") {
		t.Fatalf("expected plain-text error body, got %q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "\"success\"") {
		t.Fatalf("expected non-JSON response for websocket upgrade, got %q", rec.Body.String())
	}
}

func TestStreamLogs_InvalidServiceWithoutUpgradeReturnsJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfg := newTestConfig("crowdsec")
	router := gin.New()
	router.GET("/logs/stream/:service", StreamLogs(&docker.Client{}, cfg))

	req := httptest.NewRequest(http.MethodGet, "/logs/stream/not-crowdsec", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), "\"success\":false") {
		t.Fatalf("expected JSON error body, got %q", rec.Body.String())
	}
}
