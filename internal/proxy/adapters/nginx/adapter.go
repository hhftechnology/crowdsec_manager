package nginx

import (
	"context"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/proxy"
	adapterscommon "crowdsec-manager/internal/proxy/adapters/common"
)

// NginxAdapter implements ProxyAdapter for Nginx Proxy Manager
type NginxAdapter struct {
	config        *proxy.ProxyConfig
	dockerClient  *docker.Client
	cfg           *config.Config
	containerName string

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

	deps, err := adapterscommon.BuildAdapterDependencies(cfg, "nginx-proxy-manager")
	if err != nil {
		return err
	}

	n.dockerClient = deps.Client
	n.cfg = deps.Config
	n.containerName = deps.ContainerName

	n.logMgr = NewNginxLogManager(n.dockerClient, n.cfg)
	n.bouncerMgr = NewNginxBouncerManager(n.dockerClient, n.cfg)

	return nil
}

// HealthCheck performs a health check for Nginx Proxy Manager
func (n *NginxAdapter) HealthCheck(ctx context.Context) (*models.HealthCheckItem, error) {
	if item, err := adapterscommon.CheckContainerRunning(n.dockerClient, n.containerName, "Nginx Proxy Manager"); item != nil || err != nil {
		return item, err
	}

	return adapterscommon.BuildHealthyStatus(
		"Nginx Proxy Manager",
		proxy.ProxyTypeNginx,
		n.containerName,
		n.SupportedFeatures(),
		map[string]interface{}{},
	), nil
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
