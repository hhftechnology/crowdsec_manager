package caddy

import (
	"context"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/proxy"
	"fmt"
)

// CaddyAdapter implements ProxyAdapter for Caddy web server
type CaddyAdapter struct {
	config       *proxy.ProxyConfig
	dockerClient *docker.Client
	cfg          *config.Config
	
	// Feature managers
	bouncerMgr *CaddyBouncerManager
}

// NewCaddyAdapter creates a new Caddy adapter
func NewCaddyAdapter() proxy.ProxyAdapter {
	return &CaddyAdapter{}
}

// Name returns the adapter name
func (c *CaddyAdapter) Name() string {
	return "Caddy Web Server"
}

// Type returns the proxy type
func (c *CaddyAdapter) Type() proxy.ProxyType {
	return proxy.ProxyTypeCaddy
}

// SupportedFeatures returns the features supported by Caddy
func (c *CaddyAdapter) SupportedFeatures() []proxy.Feature {
	return []proxy.Feature{
		proxy.FeatureBouncer,
		proxy.FeatureHealth,
	}
}

// Initialize initializes the Caddy adapter
func (c *CaddyAdapter) Initialize(ctx context.Context, cfg *proxy.ProxyConfig) error {
	c.config = cfg
	
	// Extract Docker client and config from the proxy config
	if dockerClient, ok := cfg.DockerClient.(*docker.Client); ok {
		c.dockerClient = dockerClient
	} else {
		return fmt.Errorf("invalid docker client type")
	}
	
	// Create a config.Config from proxy config for compatibility
	c.cfg = &config.Config{
		CrowdsecContainerName: "crowdsec", // Default, should be configurable
	}
	
	// Set container name
	if cfg.ContainerName != "" {
		// Store Caddy container name in a custom field since config.Config doesn't have it
		c.cfg.TraefikContainerName = cfg.ContainerName // Reuse field for Caddy container
	} else {
		c.cfg.TraefikContainerName = "caddy"
	}
	
	// Initialize feature managers
	c.bouncerMgr = NewCaddyBouncerManager(c.dockerClient, c.cfg)
	
	return nil
}

// HealthCheck performs a health check for Caddy
func (c *CaddyAdapter) HealthCheck(ctx context.Context) (*models.HealthCheckItem, error) {
	if c.dockerClient == nil || c.cfg == nil {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Caddy adapter not properly initialized",
			Error:   "Docker client or config is nil",
		}, nil
	}
	
	containerName := c.cfg.TraefikContainerName // Reused field for Caddy container
	
	// Check if Caddy container is running
	isRunning, err := c.dockerClient.IsContainerRunning(containerName)
	if err != nil {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Failed to check Caddy container status",
			Error:   fmt.Sprintf("Container check error: %v", err),
		}, nil
	}
	
	if !isRunning {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Caddy container is not running",
			Details: fmt.Sprintf("Container '%s' is stopped or not found", containerName),
		}, nil
	}
	
	// Check if Caddy is responding (try to access the admin API)
	_, err = c.dockerClient.ExecCommand(containerName, []string{
		"curl", "-f", "http://localhost:2019/config/",
	})
	if err != nil {
		return &models.HealthCheckItem{
			Status:  "degraded",
			Message: "Caddy container running but admin API may be inaccessible",
			Details: "Admin API check failed",
			Error:   fmt.Sprintf("Admin API error: %v", err),
		}, nil
	}
	
	return &models.HealthCheckItem{
		Status:  "healthy",
		Message: "Caddy container is running and admin API is accessible",
		Details: fmt.Sprintf("Container: %s", containerName),
		Metrics: map[string]interface{}{
			"proxy_type":         "caddy",
			"container_name":     containerName,
			"supported_features": c.SupportedFeatures(),
		},
	}, nil
}

// WhitelistManager returns nil - Caddy doesn't support programmatic whitelist management through this adapter
func (c *CaddyAdapter) WhitelistManager() proxy.WhitelistManager {
	return nil
}

// CaptchaManager returns nil - Caddy doesn't support captcha integration through this adapter
func (c *CaddyAdapter) CaptchaManager() proxy.CaptchaManager {
	return nil
}

// LogManager returns nil - Caddy log management not implemented in this adapter
func (c *CaddyAdapter) LogManager() proxy.LogManager {
	return nil
}

// BouncerManager returns the Caddy bouncer manager
func (c *CaddyAdapter) BouncerManager() proxy.BouncerManager {
	return c.bouncerMgr
}