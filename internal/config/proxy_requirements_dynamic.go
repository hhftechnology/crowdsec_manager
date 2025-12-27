package config

import (
	"os"
	"path/filepath"
	"strings"
)

// GetProxyRequirementsFromConfig returns proxy requirements using actual config values
// This version uses real environment variable values instead of hardcoded defaults
func GetProxyRequirementsFromConfig(cfg *Config) ProxyRequirements {
	baseReqs := GetProxyRequirements(cfg.ProxyType)

	// Update paths with actual values from config
	for i := range baseReqs.RequiredPaths {
		updatePathFromConfig(&baseReqs.RequiredPaths[i], cfg)
	}

	for i := range baseReqs.OptionalPaths {
		updatePathFromConfig(&baseReqs.OptionalPaths[i], cfg)
	}

	return baseReqs
}

// updatePathFromConfig updates a PathRequirement with actual values from config
func updatePathFromConfig(req *PathRequirement, cfg *Config) {
	// Get the actual container path from environment variable
	if req.EnvVar != "" {
		if envValue := os.Getenv(req.EnvVar); envValue != "" {
			req.ContainerPath = envValue
		}
	}

	// Try to derive host path from container path and volume mappings
	// This handles cases where user has custom paths
	req.HostPath = deriveHostPath(req.ContainerPath, req.EnvVar, cfg)
}

// deriveHostPath attempts to derive the host path from container path and volume mappings
func deriveHostPath(containerPath, envVar string, cfg *Config) string {
	// Special handling for known environment variables
	switch envVar {
	case "TRAEFIK_DYNAMIC_CONFIG":
		return deriveFromTraefikConfig(containerPath, cfg.ConfigDir, "/etc/traefik")
	case "TRAEFIK_STATIC_CONFIG":
		return deriveFromTraefikConfig(containerPath, cfg.ConfigDir, "/etc/traefik")
	case "TRAEFIK_ACCESS_LOG":
		return deriveFromTraefikLogs(containerPath, cfg.ConfigDir)
	case "TRAEFIK_ERROR_LOG":
		return deriveFromTraefikLogs(containerPath, cfg.ConfigDir)
	case "TRAEFIK_CAPTCHA_HTML":
		return deriveFromTraefikConfig(containerPath, cfg.ConfigDir, "/etc/traefik")
	}

	// Default: try to derive from common volume mount patterns
	return deriveFromCommonMounts(containerPath, cfg.ConfigDir)
}

// deriveFromTraefikConfig derives host path for Traefik config files
func deriveFromTraefikConfig(containerPath, configDir, baseContainerPath string) string {
	// Strip the base container path and add to config dir
	if strings.HasPrefix(containerPath, baseContainerPath) {
		relativePath := strings.TrimPrefix(containerPath, baseContainerPath)
		relativePath = strings.TrimPrefix(relativePath, "/")
		return filepath.Join(configDir, "traefik", relativePath)
	}

	// If not in expected location, just use the filename in config/traefik
	filename := filepath.Base(containerPath)
	return filepath.Join(configDir, "traefik", filename)
}

// deriveFromTraefikLogs derives host path for Traefik log files
func deriveFromTraefikLogs(containerPath, configDir string) string {
	// Common patterns for log mounts
	// /var/log/traefik -> ./logs/traefik or ./config/traefik/logs

	if strings.HasPrefix(containerPath, "/var/log/traefik") {
		relativePath := strings.TrimPrefix(containerPath, "/var/log/traefik/")

		// Try multiple possible host locations
		// Pattern 1: ./logs/traefik (dedicated logs directory)
		// Pattern 2: ./config/traefik/logs (logs inside config)

		// For now, use config/traefik/logs as it matches the user's volume mount:
		// /root/config/traefik/logs:/var/log/traefik
		return filepath.Join(configDir, "traefik", "logs", relativePath)
	}

	// Fallback
	filename := filepath.Base(containerPath)
	return filepath.Join(configDir, "traefik", "logs", filename)
}

// deriveFromCommonMounts tries to derive host path from common volume mount patterns
func deriveFromCommonMounts(containerPath, configDir string) string {
	// Pattern: /etc/traefik -> ./config/traefik
	if strings.HasPrefix(containerPath, "/etc/traefik") {
		relativePath := strings.TrimPrefix(containerPath, "/etc/traefik/")
		return filepath.Join(configDir, "traefik", relativePath)
	}

	// Pattern: /var/log/traefik -> ./config/traefik/logs
	if strings.HasPrefix(containerPath, "/var/log/traefik") {
		relativePath := strings.TrimPrefix(containerPath, "/var/log/traefik/")
		return filepath.Join(configDir, "traefik", "logs", relativePath)
	}

	// Pattern: /etc/nginx -> ./config/nginx
	if strings.HasPrefix(containerPath, "/etc/nginx") {
		relativePath := strings.TrimPrefix(containerPath, "/etc/nginx/")
		return filepath.Join(configDir, "nginx", relativePath)
	}

	// Pattern: /etc/caddy -> ./config/caddy
	if strings.HasPrefix(containerPath, "/etc/caddy") {
		relativePath := strings.TrimPrefix(containerPath, "/etc/caddy/")
		return filepath.Join(configDir, "caddy", relativePath)
	}

	// Pattern: /etc/haproxy -> ./config/haproxy
	if strings.HasPrefix(containerPath, "/etc/haproxy") {
		relativePath := strings.TrimPrefix(containerPath, "/etc/haproxy/")
		return filepath.Join(configDir, "haproxy", relativePath)
	}

	// Fallback: just use filename in config directory
	filename := filepath.Base(containerPath)
	return filepath.Join(configDir, filename)
}
