package caddy

import (
	"context"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/proxy"
	adapterscommon "crowdsec-manager/internal/proxy/adapters/common"
	"fmt"
)

// CaddyAdapter implements ProxyAdapter for Caddy web server
type CaddyAdapter struct {
	config        *proxy.ProxyConfig
	dockerClient  *docker.Client
	cfg           *config.Config
	containerName string

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

	deps, err := adapterscommon.BuildAdapterDependencies(cfg, "caddy")
	if err != nil {
		return err
	}

	c.dockerClient = deps.Client
	c.cfg = deps.Config
	c.containerName = deps.ContainerName

	c.bouncerMgr = NewCaddyBouncerManager(c.dockerClient, c.cfg)

	return nil
}

// HealthCheck performs a health check for Caddy
func (c *CaddyAdapter) HealthCheck(ctx context.Context) (*models.HealthCheckItem, error) {
	if item, err := adapterscommon.CheckContainerRunning(c.dockerClient, c.containerName, "Caddy"); item != nil || err != nil {
		return item, err
	}

	// Check if Caddy is responding (try to access the admin API)
	_, err := c.dockerClient.ExecCommand(c.containerName, []string{
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

	return adapterscommon.BuildHealthyStatus(
		"Caddy",
		proxy.ProxyTypeCaddy,
		c.containerName,
		c.SupportedFeatures(),
		map[string]interface{}{},
	), nil
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
