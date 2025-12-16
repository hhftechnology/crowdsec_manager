package standalone

import (
	"context"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/proxy"
	"fmt"
)

// StandaloneAdapter implements ProxyAdapter for CrowdSec-only mode (no reverse proxy)
type StandaloneAdapter struct {
	config       *proxy.ProxyConfig
	dockerClient *docker.Client
	cfg          *config.Config
}

// NewStandaloneAdapter creates a new Standalone adapter
func NewStandaloneAdapter() proxy.ProxyAdapter {
	return &StandaloneAdapter{}
}

// Name returns the adapter name
func (s *StandaloneAdapter) Name() string {
	return "CrowdSec Standalone (No Reverse Proxy)"
}

// Type returns the proxy type
func (s *StandaloneAdapter) Type() proxy.ProxyType {
	return proxy.ProxyTypeStandalone
}

// SupportedFeatures returns the features supported by Standalone mode
func (s *StandaloneAdapter) SupportedFeatures() []proxy.Feature {
	return []proxy.Feature{
		proxy.FeatureHealth,
	}
}

// Initialize initializes the Standalone adapter
func (s *StandaloneAdapter) Initialize(ctx context.Context, cfg *proxy.ProxyConfig) error {
	s.config = cfg
	
	// Extract Docker client and config from the proxy config
	if dockerClient, ok := cfg.DockerClient.(*docker.Client); ok {
		s.dockerClient = dockerClient
	} else {
		return fmt.Errorf("invalid docker client type")
	}
	
	// Create a config.Config from proxy config for compatibility
	s.cfg = &config.Config{
		CrowdsecContainerName: "crowdsec", // Default, should be configurable
	}
	
	// In standalone mode, there's no proxy container
	s.cfg.TraefikContainerName = "" // No proxy container
	
	return nil
}

// HealthCheck performs a health check for Standalone mode (CrowdSec only)
func (s *StandaloneAdapter) HealthCheck(ctx context.Context) (*models.HealthCheckItem, error) {
	if s.dockerClient == nil || s.cfg == nil {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Standalone adapter not properly initialized",
			Error:   "Docker client or config is nil",
		}, nil
	}
	
	// Check if CrowdSec container is running
	isRunning, err := s.dockerClient.IsContainerRunning(s.cfg.CrowdsecContainerName)
	if err != nil {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Failed to check CrowdSec container status",
			Error:   fmt.Sprintf("Container check error: %v", err),
		}, nil
	}
	
	if !isRunning {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "CrowdSec container is not running",
			Details: fmt.Sprintf("Container '%s' is stopped or not found", s.cfg.CrowdsecContainerName),
		}, nil
	}
	
	// Check CrowdSec LAPI status
	_, err = s.dockerClient.ExecCommand(s.cfg.CrowdsecContainerName, []string{
		"cscli", "lapi", "status",
	})
	if err != nil {
		return &models.HealthCheckItem{
			Status:  "degraded",
			Message: "CrowdSec container running but LAPI may be inaccessible",
			Details: "LAPI status check failed",
			Error:   fmt.Sprintf("LAPI error: %v", err),
		}, nil
	}
	
	return &models.HealthCheckItem{
		Status:  "healthy",
		Message: "CrowdSec is running in standalone mode (no reverse proxy)",
		Details: fmt.Sprintf("CrowdSec Container: %s", s.cfg.CrowdsecContainerName),
		Metrics: map[string]interface{}{
			"proxy_type":         "standalone",
			"crowdsec_container": s.cfg.CrowdsecContainerName,
			"supported_features": s.SupportedFeatures(),
			"mode":              "crowdsec_only",
		},
	}, nil
}

// WhitelistManager returns nil - no proxy-specific whitelist management in standalone mode
func (s *StandaloneAdapter) WhitelistManager() proxy.WhitelistManager {
	return nil
}

// CaptchaManager returns nil - no captcha integration in standalone mode
func (s *StandaloneAdapter) CaptchaManager() proxy.CaptchaManager {
	return nil
}

// LogManager returns nil - no proxy log management in standalone mode
func (s *StandaloneAdapter) LogManager() proxy.LogManager {
	return nil
}

// BouncerManager returns nil - no proxy bouncer integration in standalone mode
func (s *StandaloneAdapter) BouncerManager() proxy.BouncerManager {
	return nil
}

// GetStandaloneInfo returns information about standalone mode
func (s *StandaloneAdapter) GetStandaloneInfo() map[string]interface{} {
	return map[string]interface{}{
		"mode":        "standalone",
		"description": "CrowdSec running without reverse proxy integration",
		"features": []string{
			"CrowdSec LAPI health monitoring",
			"Basic container status checking",
		},
		"limitations": []string{
			"No reverse proxy integration",
			"No proxy-specific whitelist management",
			"No captcha support",
			"No proxy log parsing",
			"No bouncer integration",
		},
		"use_cases": []string{
			"CrowdSec development and testing",
			"API-only CrowdSec deployments",
			"Custom bouncer integrations",
			"Monitoring CrowdSec without proxy",
		},
		"notes": "Standalone mode provides basic CrowdSec monitoring without reverse proxy features. " +
			"This is useful for development, testing, or custom integrations.",
	}
}

// GetCrowdSecStatus returns detailed CrowdSec status information
func (s *StandaloneAdapter) GetCrowdSecStatus(ctx context.Context) (map[string]interface{}, error) {
	if s.dockerClient == nil || s.cfg == nil {
		return nil, fmt.Errorf("adapter not properly initialized")
	}
	
	status := make(map[string]interface{})
	
	// Check container status
	isRunning, err := s.dockerClient.IsContainerRunning(s.cfg.CrowdsecContainerName)
	if err != nil {
		return nil, fmt.Errorf("failed to check container status: %w", err)
	}
	status["container_running"] = isRunning
	
	if !isRunning {
		status["error"] = "CrowdSec container is not running"
		return status, nil
	}
	
	// Check LAPI status
	lapiOutput, err := s.dockerClient.ExecCommand(s.cfg.CrowdsecContainerName, []string{
		"cscli", "lapi", "status",
	})
	if err != nil {
		status["lapi_error"] = fmt.Sprintf("LAPI check failed: %v", err)
	} else {
		status["lapi_status"] = lapiOutput
		status["lapi_healthy"] = true
	}
	
	// Get bouncers list
	bouncersOutput, err := s.dockerClient.ExecCommand(s.cfg.CrowdsecContainerName, []string{
		"cscli", "bouncers", "list", "-o", "json",
	})
	if err != nil {
		status["bouncers_error"] = fmt.Sprintf("Failed to list bouncers: %v", err)
	} else {
		status["bouncers_raw"] = bouncersOutput
		if bouncersOutput == "null" || bouncersOutput == "" || bouncersOutput == "[]" {
			status["bouncers_count"] = 0
		} else {
			status["bouncers_count"] = "unknown" // Would need JSON parsing for exact count
		}
	}
	
	// Get decisions count
	decisionsOutput, err := s.dockerClient.ExecCommand(s.cfg.CrowdsecContainerName, []string{
		"cscli", "decisions", "list", "-o", "json",
	})
	if err != nil {
		status["decisions_error"] = fmt.Sprintf("Failed to list decisions: %v", err)
	} else {
		if decisionsOutput == "null" || decisionsOutput == "" || decisionsOutput == "[]" {
			status["decisions_count"] = 0
		} else {
			status["decisions_count"] = "unknown" // Would need JSON parsing for exact count
		}
	}
	
	return status, nil
}