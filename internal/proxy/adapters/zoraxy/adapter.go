package zoraxy

import (
	"context"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/proxy"
	"fmt"
)

// ZoraxyAdapter implements ProxyAdapter for Zoraxy reverse proxy (experimental)
type ZoraxyAdapter struct {
	config       *proxy.ProxyConfig
	dockerClient *docker.Client
	cfg          *config.Config
}

// NewZoraxyAdapter creates a new Zoraxy adapter
func NewZoraxyAdapter() proxy.ProxyAdapter {
	return &ZoraxyAdapter{}
}

// Name returns the adapter name
func (z *ZoraxyAdapter) Name() string {
	return "Zoraxy Reverse Proxy (Experimental)"
}

// Type returns the proxy type
func (z *ZoraxyAdapter) Type() proxy.ProxyType {
	return proxy.ProxyTypeZoraxy
}

// SupportedFeatures returns the features supported by Zoraxy (minimal for experimental status)
func (z *ZoraxyAdapter) SupportedFeatures() []proxy.Feature {
	return []proxy.Feature{
		proxy.FeatureHealth,
	}
}

// Initialize initializes the Zoraxy adapter
func (z *ZoraxyAdapter) Initialize(ctx context.Context, cfg *proxy.ProxyConfig) error {
	z.config = cfg
	
	// Extract Docker client and config from the proxy config
	if dockerClient, ok := cfg.DockerClient.(*docker.Client); ok {
		z.dockerClient = dockerClient
	} else {
		return fmt.Errorf("invalid docker client type")
	}
	
	// Create a config.Config from proxy config for compatibility
	z.cfg = &config.Config{
		CrowdsecContainerName: "crowdsec", // Default, should be configurable
	}
	
	// Set container name
	if cfg.ContainerName != "" {
		// Store Zoraxy container name in a custom field since config.Config doesn't have it
		z.cfg.TraefikContainerName = cfg.ContainerName // Reuse field for Zoraxy container
	} else {
		z.cfg.TraefikContainerName = "zoraxy"
	}
	
	return nil
}

// HealthCheck performs a health check for Zoraxy
func (z *ZoraxyAdapter) HealthCheck(ctx context.Context) (*models.HealthCheckItem, error) {
	if z.dockerClient == nil || z.cfg == nil {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Zoraxy adapter not properly initialized",
			Error:   "Docker client or config is nil",
		}, nil
	}
	
	containerName := z.cfg.TraefikContainerName // Reused field for Zoraxy container
	
	// Check if Zoraxy container is running
	isRunning, err := z.dockerClient.IsContainerRunning(containerName)
	if err != nil {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Failed to check Zoraxy container status",
			Error:   fmt.Sprintf("Container check error: %v", err),
		}, nil
	}
	
	if !isRunning {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Zoraxy container is not running",
			Details: fmt.Sprintf("Container '%s' is stopped or not found", containerName),
		}, nil
	}
	
	// Check if Zoraxy web interface is accessible (default port 8000)
	_, err = z.dockerClient.ExecCommand(containerName, []string{
		"curl", "-f", "http://localhost:8000/api/info",
	})
	if err != nil {
		return &models.HealthCheckItem{
			Status:  "degraded",
			Message: "Zoraxy container running but web interface may be inaccessible",
			Details: "Web interface check failed",
			Error:   fmt.Sprintf("Web interface error: %v", err),
		}, nil
	}
	
	return &models.HealthCheckItem{
		Status:  "healthy",
		Message: "Zoraxy container is running and web interface is accessible",
		Details: fmt.Sprintf("Container: %s (Experimental)", containerName),
		Metrics: map[string]interface{}{
			"proxy_type":         "zoraxy",
			"container_name":     containerName,
			"supported_features": z.SupportedFeatures(),
			"experimental":       true,
		},
	}, nil
}

// WhitelistManager returns nil - Zoraxy whitelist management not implemented (experimental)
func (z *ZoraxyAdapter) WhitelistManager() proxy.WhitelistManager {
	return nil
}

// CaptchaManager returns nil - Zoraxy captcha integration not implemented (experimental)
func (z *ZoraxyAdapter) CaptchaManager() proxy.CaptchaManager {
	return nil
}

// LogManager returns nil - Zoraxy log management not implemented (experimental)
func (z *ZoraxyAdapter) LogManager() proxy.LogManager {
	return nil
}

// BouncerManager returns nil - Zoraxy bouncer integration not implemented (experimental)
func (z *ZoraxyAdapter) BouncerManager() proxy.BouncerManager {
	return nil
}

// GetExperimentalStatus returns information about the experimental status
func (z *ZoraxyAdapter) GetExperimentalStatus() map[string]interface{} {
	return map[string]interface{}{
		"experimental":     true,
		"status":          "basic health monitoring only",
		"planned_features": []string{
			"Basic container health checking",
			"Web interface connectivity verification",
		},
		"limitations": []string{
			"No CrowdSec bouncer integration",
			"No whitelist management",
			"No captcha support",
			"No log parsing",
		},
		"notes": "Zoraxy integration is experimental and provides minimal functionality. " +
			"This adapter serves as a foundation for future development.",
	}
}