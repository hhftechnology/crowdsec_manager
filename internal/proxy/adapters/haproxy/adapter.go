package haproxy

import (
	"context"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/proxy"
	"fmt"
)

// HAProxyAdapter implements ProxyAdapter for HAProxy with SPOA bouncer integration
type HAProxyAdapter struct {
	config       *proxy.ProxyConfig
	dockerClient *docker.Client
	cfg          *config.Config
	
	// Feature managers
	bouncerMgr *HAProxyBouncerManager
}

// NewHAProxyAdapter creates a new HAProxy adapter
func NewHAProxyAdapter() proxy.ProxyAdapter {
	return &HAProxyAdapter{}
}

// Name returns the adapter name
func (h *HAProxyAdapter) Name() string {
	return "HAProxy Load Balancer"
}

// Type returns the proxy type
func (h *HAProxyAdapter) Type() proxy.ProxyType {
	return proxy.ProxyTypeHAProxy
}

// SupportedFeatures returns the features supported by HAProxy
func (h *HAProxyAdapter) SupportedFeatures() []proxy.Feature {
	return []proxy.Feature{
		proxy.FeatureBouncer,
		proxy.FeatureHealth,
	}
}

// Initialize initializes the HAProxy adapter
func (h *HAProxyAdapter) Initialize(ctx context.Context, cfg *proxy.ProxyConfig) error {
	h.config = cfg
	
	// Extract Docker client and config from the proxy config
	if dockerClient, ok := cfg.DockerClient.(*docker.Client); ok {
		h.dockerClient = dockerClient
	} else {
		return fmt.Errorf("invalid docker client type")
	}
	
	// Create a config.Config from proxy config for compatibility
	h.cfg = &config.Config{
		CrowdsecContainerName: "crowdsec", // Default, should be configurable
	}
	
	// Set container name
	if cfg.ContainerName != "" {
		// Store HAProxy container name in a custom field since config.Config doesn't have it
		h.cfg.TraefikContainerName = cfg.ContainerName // Reuse field for HAProxy container
	} else {
		h.cfg.TraefikContainerName = "haproxy"
	}
	
	// Initialize feature managers
	h.bouncerMgr = NewHAProxyBouncerManager(h.dockerClient, h.cfg)
	
	return nil
}

// HealthCheck performs a health check for HAProxy
func (h *HAProxyAdapter) HealthCheck(ctx context.Context) (*models.HealthCheckItem, error) {
	if h.dockerClient == nil || h.cfg == nil {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "HAProxy adapter not properly initialized",
			Error:   "Docker client or config is nil",
		}, nil
	}
	
	containerName := h.cfg.TraefikContainerName // Reused field for HAProxy container
	
	// Check if HAProxy container is running
	isRunning, err := h.dockerClient.IsContainerRunning(containerName)
	if err != nil {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Failed to check HAProxy container status",
			Error:   fmt.Sprintf("Container check error: %v", err),
		}, nil
	}
	
	if !isRunning {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "HAProxy container is not running",
			Details: fmt.Sprintf("Container '%s' is stopped or not found", containerName),
		}, nil
	}
	
	// Check if HAProxy stats socket is accessible (if configured)
	_, err = h.dockerClient.ExecCommand(containerName, []string{
		"sh", "-c", "echo 'show info' | socat stdio /var/run/haproxy/admin.sock",
	})
	if err != nil {
		return &models.HealthCheckItem{
			Status:  "degraded",
			Message: "HAProxy container running but stats socket may be inaccessible",
			Details: "Stats socket check failed",
			Error:   fmt.Sprintf("Stats socket error: %v", err),
		}, nil
	}
	
	return &models.HealthCheckItem{
		Status:  "healthy",
		Message: "HAProxy container is running and stats socket is accessible",
		Details: fmt.Sprintf("Container: %s", containerName),
		Metrics: map[string]interface{}{
			"proxy_type":         "haproxy",
			"container_name":     containerName,
			"supported_features": h.SupportedFeatures(),
		},
	}, nil
}

// WhitelistManager returns nil - HAProxy doesn't support programmatic whitelist management through this adapter
func (h *HAProxyAdapter) WhitelistManager() proxy.WhitelistManager {
	return nil
}

// CaptchaManager returns nil - HAProxy doesn't support captcha integration through this adapter
func (h *HAProxyAdapter) CaptchaManager() proxy.CaptchaManager {
	return nil
}

// LogManager returns nil - HAProxy log management not implemented in this adapter
func (h *HAProxyAdapter) LogManager() proxy.LogManager {
	return nil
}

// BouncerManager returns the HAProxy bouncer manager
func (h *HAProxyAdapter) BouncerManager() proxy.BouncerManager {
	return h.bouncerMgr
}