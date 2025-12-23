package traefik

import (
	"context"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/proxy"
	"fmt"
)

// TraefikAdapter implements ProxyAdapter for Traefik reverse proxy
type TraefikAdapter struct {
	config       *proxy.ProxyConfig
	dockerClient *docker.Client
	cfg          *config.Config
	
	// Feature managers
	whitelistMgr *TraefikWhitelistManager
	captchaMgr   *TraefikCaptchaManager
	logMgr       *TraefikLogManager
	bouncerMgr   *TraefikBouncerManager
}

// NewTraefikAdapter creates a new Traefik adapter
func NewTraefikAdapter() proxy.ProxyAdapter {
	return &TraefikAdapter{}
}

// Name returns the adapter name
func (t *TraefikAdapter) Name() string {
	return "Traefik Reverse Proxy"
}

// Type returns the proxy type
func (t *TraefikAdapter) Type() proxy.ProxyType {
	return proxy.ProxyTypeTraefik
}

// SupportedFeatures returns the features supported by Traefik
func (t *TraefikAdapter) SupportedFeatures() []proxy.Feature {
	return []proxy.Feature{
		proxy.FeatureWhitelist,
		proxy.FeatureCaptcha,
		proxy.FeatureLogs,
		proxy.FeatureBouncer,
		proxy.FeatureHealth,
		proxy.FeatureAppSec,
	}
}

// Initialize initializes the Traefik adapter
func (t *TraefikAdapter) Initialize(ctx context.Context, cfg *proxy.ProxyConfig) error {
	t.config = cfg
	
	// Extract Docker client and config from the proxy config
	if dockerClient, ok := cfg.DockerClient.(*docker.Client); ok {
		t.dockerClient = dockerClient
	} else {
		return fmt.Errorf("invalid docker client type")
	}
	
	// Create a config.Config from proxy config for compatibility
	t.cfg = &config.Config{
		TraefikContainerName:  cfg.ContainerName,
		CrowdsecContainerName: "crowdsec", // Default, should be configurable
		Paths:                 config.NewPathConfig(), // Initialize with defaults
	}

	// Set config paths if provided (override defaults)
	if dynamicPath, exists := cfg.ConfigPaths["dynamic"]; exists {
		t.cfg.Paths.TraefikDynamicConfig = dynamicPath
		t.cfg.TraefikDynamicConfig = dynamicPath // Backward compatibility
	}
	if staticPath, exists := cfg.ConfigPaths["static"]; exists {
		t.cfg.Paths.TraefikStaticConfig = staticPath
		t.cfg.TraefikStaticConfig = staticPath // Backward compatibility
	}
	if accessLogPath, exists := cfg.ConfigPaths["access_log"]; exists {
		t.cfg.Paths.TraefikAccessLog = accessLogPath
		t.cfg.TraefikAccessLog = accessLogPath // Backward compatibility
	}
	if errorLogPath, exists := cfg.ConfigPaths["error_log"]; exists {
		t.cfg.Paths.TraefikErrorLog = errorLogPath
		t.cfg.TraefikErrorLog = errorLogPath // Backward compatibility
	}
	if captchaPath, exists := cfg.ConfigPaths["captcha_html"]; exists {
		t.cfg.Paths.TraefikCaptchaHTML = captchaPath
	}
	if confDir, exists := cfg.ConfigPaths["conf_dir"]; exists {
		t.cfg.Paths.TraefikConfDir = confDir
	}
	
	// Initialize feature managers
	t.whitelistMgr = NewTraefikWhitelistManager(t.dockerClient, t.cfg)
	t.captchaMgr = NewTraefikCaptchaManager(t.dockerClient, t.cfg)
	t.logMgr = NewTraefikLogManager(t.dockerClient, t.cfg)
	t.bouncerMgr = NewTraefikBouncerManager(t.dockerClient, t.cfg)
	
	return nil
}

// HealthCheck performs a health check for Traefik
func (t *TraefikAdapter) HealthCheck(ctx context.Context) (*models.HealthCheckItem, error) {
	if t.dockerClient == nil || t.cfg == nil {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Traefik adapter not properly initialized",
			Error:   "Docker client or config is nil",
		}, nil
	}
	
	// Check if Traefik container is running
	isRunning, err := t.dockerClient.IsContainerRunning(t.cfg.TraefikContainerName)
	if err != nil {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Failed to check Traefik container status",
			Error:   fmt.Sprintf("Container check error: %v", err),
		}, nil
	}
	
	if !isRunning {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Traefik container is not running",
			Details: fmt.Sprintf("Container '%s' is stopped or not found", t.cfg.TraefikContainerName),
		}, nil
	}
	
	// Check if dynamic config file exists and is readable
	dynamicConfigPath := t.cfg.Paths.TraefikDynamicConfig
	_, err = t.dockerClient.ExecCommand(t.cfg.TraefikContainerName, []string{
		"cat", dynamicConfigPath,
	})
	if err != nil {
		return &models.HealthCheckItem{
			Status:  "degraded",
			Message: "Traefik container running but configuration may be inaccessible",
			Details: fmt.Sprintf("Dynamic configuration file could not be read: %s", dynamicConfigPath),
			Error:   fmt.Sprintf("Config read error: %v", err),
		}, nil
	}
	
	return &models.HealthCheckItem{
		Status:  "healthy",
		Message: "Traefik container is running and accessible",
		Details: fmt.Sprintf("Container: %s", t.cfg.TraefikContainerName),
		Metrics: map[string]interface{}{
			"proxy_type":         "traefik",
			"container_name":     t.cfg.TraefikContainerName,
			"supported_features": t.SupportedFeatures(),
		},
	}, nil
}

// WhitelistManager returns the Traefik whitelist manager
func (t *TraefikAdapter) WhitelistManager() proxy.WhitelistManager {
	return t.whitelistMgr
}

// CaptchaManager returns the Traefik captcha manager
func (t *TraefikAdapter) CaptchaManager() proxy.CaptchaManager {
	return t.captchaMgr
}

// LogManager returns the Traefik log manager
func (t *TraefikAdapter) LogManager() proxy.LogManager {
	return t.logMgr
}

// BouncerManager returns the Traefik bouncer manager
func (t *TraefikAdapter) BouncerManager() proxy.BouncerManager {
	return t.bouncerMgr
}