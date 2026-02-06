package proxy

import (
	"crowdsec-manager/internal/config"
)

// ResolveConfig creates a ProxyConfig from the application configuration
// and the selected proxy type. This centralizes the proxy selection logic
// that was previously spread across main.go.
func ResolveConfig(cfg *config.Config, proxyType ProxyType, dockerClient interface{}) *ProxyConfig {
	pc := &ProxyConfig{
		Type:           proxyType,
		Enabled:        true,
		CustomSettings: make(map[string]string),
		DockerClient:   dockerClient,
	}

	// Resolve container name based on proxy type
	switch proxyType {
	case ProxyTypeTraefik:
		pc.ContainerName = cfg.TraefikContainerName
		pc.ConfigPaths = map[string]string{
			"dynamic":    cfg.Paths.TraefikDynamicConfig,
			"static":     cfg.Paths.TraefikStaticConfig,
			"access_log": cfg.Paths.TraefikAccessLog,
			"error_log":  cfg.Paths.TraefikErrorLog,
		}
	case ProxyTypeNginx:
		pc.ContainerName = resolveContainerName(cfg.ProxyContainerName, "nginx-proxy-manager")
		pc.ConfigPaths = map[string]string{}
	case ProxyTypeCaddy:
		pc.ContainerName = resolveContainerName(cfg.ProxyContainerName, "caddy")
		pc.ConfigPaths = map[string]string{}
	case ProxyTypeHAProxy:
		pc.ContainerName = resolveContainerName(cfg.ProxyContainerName, "haproxy")
		pc.ConfigPaths = map[string]string{}
	case ProxyTypeZoraxy:
		pc.ContainerName = resolveContainerName(cfg.ProxyContainerName, "zoraxy")
		pc.ConfigPaths = map[string]string{}
	case ProxyTypeStandalone:
		pc.ContainerName = ""
		pc.ConfigPaths = map[string]string{}
	default:
		pc.ContainerName = ""
		pc.ConfigPaths = map[string]string{}
	}

	return pc
}

// resolveContainerName returns the configured name if set, otherwise the default.
func resolveContainerName(configured, defaultName string) string {
	if configured != "" {
		return configured
	}
	return defaultName
}

// ResolveProxyType determines the proxy type from configuration,
// defaulting to Traefik for backward compatibility.
func ResolveProxyType(cfgProxyType string) ProxyType {
	if cfgProxyType == "" {
		return ProxyTypeTraefik
	}
	if err := ValidateProxyType(cfgProxyType); err != nil {
		return ProxyTypeTraefik
	}
	return ProxyType(cfgProxyType)
}
