package nginx

import (
	"context"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/proxy"
	"fmt"
)

// NginxAdapter implements ProxyAdapter for Nginx Proxy Manager
type NginxAdapter struct {
	config       *proxy.ProxyConfig
	dockerClient *docker.Client
	cfg          *config.Config
	
	// Feature managers
	logMgr     *NginxLogManager
	bouncerMgr *NginxBouncerManager
}

// NewNginxAdapter creates a new Nginx Proxy Manager adapter
func NewNginxAdapter() proxy.ProxyAdapter {
	return &NginxAdapter{}
}

// Name returns the adapter name
func (n *NginxAdapter) Name() string {
	return "Nginx Proxy Manager"
}

// Type returns the proxy type
func (n *NginxAdapter) Type() proxy.ProxyType {
	return proxy.ProxyTypeNginx
}

// SupportedFeatures returns the features supported by Nginx Proxy Manager
func (n *NginxAdapter) SupportedFeatures() []proxy.Feature {
	return []proxy.Feature{
		proxy.FeatureLogs,
		proxy.FeatureBouncer,
		proxy.FeatureHealth,
	}
}

// Initialize initializes the Nginx adapter
func (n *NginxAdapter) Initialize(ctx context.Context, cfg *proxy.ProxyConfig) error {
	n.config = cfg
	
	// Extract Docker client and config from the proxy config
	if dockerClient, ok := cfg.DockerClient.(*docker.Client); ok {
		n.dockerClient = dockerClient
	} else {
		return fmt.Errorf("invalid docker client type")
	}
	
	// Create a config.Config from proxy config for compatibility
	n.cfg = &config.Config{
		CrowdsecContainerName: "crowdsec", // Default, should be configurable
	}
	
	// Set container name
	if cfg.ContainerName != "" {
		// Store NPM container name in a custom field since config.Config doesn't have it
		n.cfg.TraefikContainerName = cfg.ContainerName // Reuse field for NPM container
	} else {
		n.cfg.TraefikContainerName = "nginx-proxy-manager"
	}
	
	// Initialize feature managers
	n.logMgr = NewNginxLogManager(n.dockerClient, n.cfg)
	n.bouncerMgr = NewNginxBouncerManager(n.dockerClient, n.cfg)
	
	return nil
}

// HealthCheck performs a health check for Nginx Proxy Manager
func (n *NginxAdapter) HealthCheck(ctx context.Context) (*models.HealthCheckItem, error) {
	if n.dockerClient == nil || n.cfg == nil {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Nginx adapter not properly initialized",
			Error:   "Docker client or config is nil",
		}, nil
	}
	
	containerName := n.cfg.TraefikContainerName // Reused field for NPM container
	
	// Check if NPM container is running
	isRunning, err := n.dockerClient.IsContainerRunning(containerName)
	if err != nil {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Failed to check Nginx Proxy Manager container status",
			Error:   fmt.Sprintf("Container check error: %v", err),
		}, nil
	}
	
	if !isRunning {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Nginx Proxy Manager container is not running",
			Details: fmt.Sprintf("Container '%s' is stopped or not found", containerName),
		}, nil
	}
	
	// Check if NPM is responding (try to access the web interface port)
	// This is a basic check - in a real implementation you might want to check the API
	return &models.HealthCheckItem{
		Status:  "healthy",
		Message: "Nginx Proxy Manager container is running",
		Details: fmt.Sprintf("Container: %s", containerName),
		Metrics: map[string]interface{}{
			"proxy_type":         "nginx",
			"container_name":     containerName,
			"supported_features": n.SupportedFeatures(),
		},
	}, nil
}

// WhitelistManager returns nil - NPM doesn't support programmatic whitelist management
func (n *NginxAdapter) WhitelistManager() proxy.WhitelistManager {
	return nil
}

// CaptchaManager returns nil - NPM doesn't support captcha integration
func (n *NginxAdapter) CaptchaManager() proxy.CaptchaManager {
	return nil
}

// LogManager returns the Nginx log manager
func (n *NginxAdapter) LogManager() proxy.LogManager {
	return n.logMgr
}

// BouncerManager returns the Nginx bouncer manager
func (n *NginxAdapter) BouncerManager() proxy.BouncerManager {
	return n.bouncerMgr
}