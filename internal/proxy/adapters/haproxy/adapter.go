package haproxy

import (
	"context"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/proxy"
	adapterscommon "crowdsec-manager/internal/proxy/adapters/common"
	"fmt"
)

// HAProxyAdapter implements ProxyAdapter for HAProxy with SPOA bouncer integration
type HAProxyAdapter struct {
	config        *proxy.ProxyConfig
	dockerClient  *docker.Client
	cfg           *config.Config
	containerName string

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

	deps, err := adapterscommon.BuildAdapterDependencies(cfg, "haproxy")
	if err != nil {
		return err
	}

	h.dockerClient = deps.Client
	h.cfg = deps.Config
	h.containerName = deps.ContainerName

	h.bouncerMgr = NewHAProxyBouncerManager(h.dockerClient, h.cfg)

	return nil
}

// HealthCheck performs a health check for HAProxy
func (h *HAProxyAdapter) HealthCheck(ctx context.Context) (*models.HealthCheckItem, error) {
	if item, err := adapterscommon.CheckContainerRunning(h.dockerClient, h.containerName, "HAProxy"); item != nil || err != nil {
		return item, err
	}

	// Check if HAProxy stats socket is accessible (if configured)
	_, err := h.dockerClient.ExecCommand(h.containerName, []string{
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

	return adapterscommon.BuildHealthyStatus(
		"HAProxy",
		proxy.ProxyTypeHAProxy,
		h.containerName,
		h.SupportedFeatures(),
		map[string]interface{}{},
	), nil
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
