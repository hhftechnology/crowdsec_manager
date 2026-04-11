package handlers

import (
	"testing"

	"crowdsec-manager/internal/config"
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