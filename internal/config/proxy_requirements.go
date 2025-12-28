package config

// GetProxyRequirements returns the validation requirements for a specific proxy type
func GetProxyRequirements(proxyType string) ProxyRequirements {
	requirements := map[string]ProxyRequirements{
		"traefik": {
			ProxyType: "traefik",
			RequiredEnvVars: []string{
				"TRAEFIK_CONTAINER_NAME",
				"TRAEFIK_DYNAMIC_CONFIG",
				"TRAEFIK_STATIC_CONFIG",
			},
			OptionalEnvVars: []string{
				"TRAEFIK_ACCESS_LOG",
				"TRAEFIK_ERROR_LOG",
				"TRAEFIK_CAPTCHA_HTML",
				"TRAEFIK_ASSETS_DIR",
				"TRAEFIK_RULES_DIR",
				"TRAEFIK_CONF_DIR",
				"TRAEFIK_HTTP_PORT",
				"TRAEFIK_HTTPS_PORT",
				"TRAEFIK_DASHBOARD_PORT",
				"TRAEFIK_API_INSECURE",
				"TRAEFIK_LOG_LEVEL",
				"TRAEFIK_VERSION",
				"TRAEFIK_HOST",
			},
			RequiredPaths: []PathRequirement{
				{
					EnvVar:        "TRAEFIK_DYNAMIC_CONFIG",
					DefaultPath:   "/etc/traefik/dynamic_config.yml",
					Type:          "file",
					Required:      true,
					Description:   "Traefik dynamic configuration file",
					HostPath:      "./config/traefik/dynamic_config.yml",
					ContainerPath: "/etc/traefik/dynamic_config.yml",
					FeatureNeeded: "whitelist",
				},
				{
					EnvVar:        "TRAEFIK_STATIC_CONFIG",
					DefaultPath:   "/etc/traefik/traefik.yml",
					Type:          "file",
					Required:      true,
					Description:   "Traefik static configuration file",
					HostPath:      "./config/traefik/traefik.yml",
					ContainerPath: "/etc/traefik/traefik.yml",
					FeatureNeeded: "health",
				},
			},
			OptionalPaths: []PathRequirement{
				{
					EnvVar:        "TRAEFIK_ACCESS_LOG",
					DefaultPath:   "/var/log/traefik/access.log",
					Type:          "file",
					Required:      false,
					Description:   "Traefik access log file",
					HostPath:      "./logs/traefik/access.log",
					ContainerPath: "/var/log/traefik/access.log",
					FeatureNeeded: "logs",
				},
				{
					EnvVar:        "TRAEFIK_ERROR_LOG",
					DefaultPath:   "/var/log/traefik/traefik.log",
					Type:          "file",
					Required:      false,
					Description:   "Traefik error log file",
					HostPath:      "./logs/traefik/traefik.log",
					ContainerPath: "/var/log/traefik/traefik.log",
					FeatureNeeded: "logs",
				},
				{
					EnvVar:        "TRAEFIK_CAPTCHA_HTML",
					DefaultPath:   "/etc/traefik/assets/captcha.html",
					Type:          "file",
					Required:      false,
					Description:   "Captcha HTML template file",
					HostPath:      "./config/traefik/assets/captcha.html",
					ContainerPath: "/etc/traefik/assets/captcha.html",
					FeatureNeeded: "captcha",
				},
				{
					EnvVar:        "TRAEFIK_ASSETS_DIR",
					DefaultPath:   "/etc/traefik/assets",
					Type:          "directory",
					Required:      false,
					Description:   "Traefik assets directory",
					HostPath:      "./config/traefik/assets",
					ContainerPath: "/etc/traefik/assets",
					FeatureNeeded: "captcha",
				},
			},
			RequiredVolumes: []VolumeRequirement{
				{
					HostPath:      "./config/traefik",
					ContainerPath: "/etc/traefik",
					Mode:          "ro",
					Required:      true,
					Description:   "Traefik configuration directory",
				},
				{
					HostPath:      "./logs/traefik",
					ContainerPath: "/var/log/traefik",
					Mode:          "rw",
					Required:      false,
					Description:   "Traefik logs directory",
				},
			},
			Features: []string{"whitelist", "captcha", "logs", "bouncer", "health", "appsec"},
		},
		"nginx": {
			ProxyType: "nginx",
			RequiredEnvVars: []string{
				"NPM_CONTAINER_NAME",
				"NGINX_CONFIG_PATH",
			},
			OptionalEnvVars: []string{
				"NGINX_LOG_PATH",
				"NPM_HTTP_PORT",
				"NPM_HTTPS_PORT",
				"NPM_ADMIN_PORT",
				"NPM_DISABLE_IPV6",
				"NPM_VERSION",
			},
			RequiredPaths: []PathRequirement{
				{
					EnvVar:        "NGINX_CONFIG_PATH",
					DefaultPath:   "/data/nginx",
					Type:          "directory",
					Required:      true,
					Description:   "Nginx Proxy Manager configuration directory",
					HostPath:      "./data/npm/nginx",
					ContainerPath: "/data/nginx",
					FeatureNeeded: "health",
				},
			},
			OptionalPaths: []PathRequirement{
				{
					EnvVar:        "NGINX_LOG_PATH",
					DefaultPath:   "/data/logs",
					Type:          "directory",
					Required:      false,
					Description:   "Nginx Proxy Manager logs directory",
					HostPath:      "./data/npm/logs",
					ContainerPath: "/data/logs",
					FeatureNeeded: "logs",
				},
			},
			RequiredVolumes: []VolumeRequirement{
				{
					HostPath:      "./data/npm",
					ContainerPath: "/data",
					Mode:          "rw",
					Required:      true,
					Description:   "Nginx Proxy Manager data directory",
				},
			},
			Features: []string{"logs", "bouncer", "health"},
		},
		"caddy": {
			ProxyType: "caddy",
			RequiredEnvVars: []string{
				"CADDY_CONTAINER_NAME",
				"CADDY_CONFIG_PATH",
			},
			OptionalEnvVars: []string{
				"CADDY_LOG_PATH",
				"CADDY_HTTP_PORT",
				"CADDY_HTTPS_PORT",
				"CADDY_ADMIN_PORT",
				"CADDY_ADMIN",
				"CADDY_VERSION",
			},
			RequiredPaths: []PathRequirement{
				{
					EnvVar:        "CADDY_CONFIG_PATH",
					DefaultPath:   "/etc/caddy",
					Type:          "directory",
					Required:      true,
					Description:   "Caddy configuration directory",
					HostPath:      "./config/caddy",
					ContainerPath: "/etc/caddy",
					FeatureNeeded: "health",
				},
			},
			OptionalPaths: []PathRequirement{
				{
					EnvVar:        "CADDY_LOG_PATH",
					DefaultPath:   "/var/log/caddy",
					Type:          "directory",
					Required:      false,
					Description:   "Caddy logs directory",
					HostPath:      "./logs/caddy",
					ContainerPath: "/var/log/caddy",
					FeatureNeeded: "logs",
				},
			},
			RequiredVolumes: []VolumeRequirement{
				{
					HostPath:      "./config/caddy",
					ContainerPath: "/etc/caddy",
					Mode:          "ro",
					Required:      true,
					Description:   "Caddy configuration directory",
				},
			},
			Features: []string{"bouncer", "health"},
		},
		"haproxy": {
			ProxyType: "haproxy",
			RequiredEnvVars: []string{
				"HAPROXY_CONTAINER_NAME",
				"HAPROXY_CONFIG_PATH",
			},
			OptionalEnvVars: []string{
				"HAPROXY_SOCKET_PATH",
				"HAPROXY_HTTP_PORT",
				"HAPROXY_HTTPS_PORT",
				"HAPROXY_STATS_PORT",
				"HAPROXY_VERSION",
			},
			RequiredPaths: []PathRequirement{
				{
					EnvVar:        "HAPROXY_CONFIG_PATH",
					DefaultPath:   "/usr/local/etc/haproxy",
					Type:          "directory",
					Required:      true,
					Description:   "HAProxy configuration directory",
					HostPath:      "./config/haproxy",
					ContainerPath: "/usr/local/etc/haproxy",
					FeatureNeeded: "health",
				},
			},
			OptionalPaths: []PathRequirement{
				{
					EnvVar:        "HAPROXY_SOCKET_PATH",
					DefaultPath:   "/var/run/haproxy.sock",
					Type:          "file",
					Required:      false,
					Description:   "HAProxy admin socket",
					HostPath:      "",
					ContainerPath: "/var/run/haproxy.sock",
					FeatureNeeded: "bouncer",
				},
			},
			RequiredVolumes: []VolumeRequirement{
				{
					HostPath:      "./config/haproxy",
					ContainerPath: "/usr/local/etc/haproxy",
					Mode:          "ro",
					Required:      true,
					Description:   "HAProxy configuration directory",
				},
			},
			Features: []string{"bouncer", "health"},
		},
		"zoraxy": {
			ProxyType: "zoraxy",
			RequiredEnvVars: []string{
				"ZORAXY_CONTAINER_NAME",
				"ZORAXY_CONFIG_PATH",
			},
			OptionalEnvVars: []string{
				"ZORAXY_HTTP_PORT",
				"ZORAXY_HTTPS_PORT",
				"ZORAXY_ADMIN_PORT",
				"ZORAXY_VERSION",
			},
			RequiredPaths: []PathRequirement{
				{
					EnvVar:        "ZORAXY_CONFIG_PATH",
					DefaultPath:   "/opt/zoraxy",
					Type:          "directory",
					Required:      true,
					Description:   "Zoraxy configuration directory",
					HostPath:      "./config/zoraxy",
					ContainerPath: "/opt/zoraxy",
					FeatureNeeded: "health",
				},
			},
			OptionalPaths: []PathRequirement{},
			RequiredVolumes: []VolumeRequirement{
				{
					HostPath:      "./config/zoraxy",
					ContainerPath: "/opt/zoraxy/config",
					Mode:          "rw",
					Required:      true,
					Description:   "Zoraxy configuration directory",
				},
			},
			Features: []string{"health"},
		},
		"standalone": {
			ProxyType:        "standalone",
			RequiredEnvVars:  []string{"CROWDSEC_CONTAINER_NAME"},
			OptionalEnvVars:  []string{},
			RequiredPaths:    []PathRequirement{},
			OptionalPaths:    []PathRequirement{},
			RequiredVolumes:  []VolumeRequirement{},
			Features:         []string{"health"},
		},
	}

	if req, ok := requirements[proxyType]; ok {
		return req
	}

	// Return standalone as default
	return requirements["standalone"]
}

// GetAllProxyRequirements returns requirements for all proxy types
func GetAllProxyRequirements() map[string]ProxyRequirements {
	return map[string]ProxyRequirements{
		"traefik":    GetProxyRequirements("traefik"),
		"nginx":      GetProxyRequirements("nginx"),
		"caddy":      GetProxyRequirements("caddy"),
		"haproxy":    GetProxyRequirements("haproxy"),
		"zoraxy":     GetProxyRequirements("zoraxy"),
		"standalone": GetProxyRequirements("standalone"),
	}
}

// GetEnvVarDescription returns a human-readable description for an env var
func GetEnvVarDescription(envVar string) string {
	descriptions := map[string]string{
		// Traefik
		"TRAEFIK_CONTAINER_NAME": "Container name for Traefik proxy",
		"TRAEFIK_DYNAMIC_CONFIG": "Path to dynamic configuration file inside Traefik container",
		"TRAEFIK_STATIC_CONFIG":  "Path to static configuration file inside Traefik container",
		"TRAEFIK_ACCESS_LOG":     "Path to access log file inside Traefik container",
		"TRAEFIK_ERROR_LOG":      "Path to error log file inside Traefik container",
		"TRAEFIK_CAPTCHA_HTML":   "Path to captcha HTML template inside Traefik container",
		"TRAEFIK_ASSETS_DIR":     "Path to assets directory inside Traefik container",
		"TRAEFIK_HTTP_PORT":      "HTTP port for Traefik (default: 80)",
		"TRAEFIK_HTTPS_PORT":     "HTTPS port for Traefik (default: 443)",
		"TRAEFIK_DASHBOARD_PORT": "Dashboard port for Traefik (default: 8081)",

		// Nginx
		"NPM_CONTAINER_NAME": "Container name for Nginx Proxy Manager",
		"NGINX_CONFIG_PATH":  "Path to config directory inside NPM container",
		"NGINX_LOG_PATH":     "Path to logs directory inside NPM container",
		"NPM_HTTP_PORT":      "HTTP port for NPM (default: 80)",
		"NPM_HTTPS_PORT":     "HTTPS port for NPM (default: 443)",
		"NPM_ADMIN_PORT":     "Admin interface port for NPM (default: 81)",

		// Caddy
		"CADDY_CONTAINER_NAME": "Container name for Caddy",
		"CADDY_CONFIG_PATH":    "Path to config directory inside Caddy container",
		"CADDY_LOG_PATH":       "Path to logs directory inside Caddy container",
		"CADDY_HTTP_PORT":      "HTTP port for Caddy (default: 80)",
		"CADDY_HTTPS_PORT":     "HTTPS port for Caddy (default: 443)",
		"CADDY_ADMIN_PORT":     "Admin API port for Caddy (default: 2019)",

		// HAProxy
		"HAPROXY_CONTAINER_NAME": "Container name for HAProxy",
		"HAPROXY_CONFIG_PATH":    "Path to config directory inside HAProxy container",
		"HAPROXY_SOCKET_PATH":    "Path to admin socket inside HAProxy container",
		"HAPROXY_HTTP_PORT":      "HTTP port for HAProxy (default: 80)",
		"HAPROXY_HTTPS_PORT":     "HTTPS port for HAProxy (default: 443)",

		// Zoraxy
		"ZORAXY_CONTAINER_NAME": "Container name for Zoraxy",
		"ZORAXY_CONFIG_PATH":    "Path to config directory inside Zoraxy container",
		"ZORAXY_HTTP_PORT":      "HTTP port for Zoraxy (default: 80)",
		"ZORAXY_HTTPS_PORT":     "HTTPS port for Zoraxy (default: 443)",
		"ZORAXY_ADMIN_PORT":     "Admin interface port for Zoraxy (default: 8000)",

		// CrowdSec
		"CROWDSEC_CONTAINER_NAME": "Container name for CrowdSec",
		"CROWDSEC_ACQUIS_FILE":    "Path to acquisition file inside CrowdSec container",
		"CROWDSEC_ACQUIS_DIR":     "Path to acquisition directory inside CrowdSec container",
		"CROWDSEC_CONFIG_DIR":     "Path to config directory inside CrowdSec container",

		// Manager
		"MANAGER_PORT":       "Port for CrowdSec Manager web interface (default: 8080)",
		"MANAGER_CONFIG_DIR": "Path to config directory inside Manager container",
		"MANAGER_DATA_DIR":   "Path to data directory inside Manager container",
		"MANAGER_BACKUP_DIR": "Path to backups directory inside Manager container",
		"MANAGER_LOG_DIR":    "Path to logs directory inside Manager container",

		// Core
		"PROXY_TYPE":    "Type of reverse proxy (traefik|nginx|caddy|haproxy|zoraxy|standalone)",
		"PROXY_ENABLED": "Enable proxy integration (true/false)",
		"ENVIRONMENT":   "Environment mode (production/development)",
		"LOG_LEVEL":     "Logging level (debug|info|warn|error)",
	}

	if desc, ok := descriptions[envVar]; ok {
		return desc
	}
	return "No description available"
}

// GetEnvVarImpact returns the impact of a missing environment variable
func GetEnvVarImpact(envVar string, proxyType string) string {
	impacts := map[string]string{
		"TRAEFIK_DYNAMIC_CONFIG": "Whitelist management and captcha features will not work",
		"TRAEFIK_STATIC_CONFIG":  "Cannot validate Traefik configuration",
		"TRAEFIK_ACCESS_LOG":     "Log parsing and analysis features will not work",
		"TRAEFIK_CAPTCHA_HTML":   "Captcha protection cannot be configured",
		"NGINX_CONFIG_PATH":      "Cannot manage Nginx Proxy Manager configuration",
		"NGINX_LOG_PATH":         "Log parsing features will not work",
		"CADDY_CONFIG_PATH":      "Cannot manage Caddy configuration",
		"HAPROXY_CONFIG_PATH":    "Cannot manage HAProxy configuration",
		"HAPROXY_SOCKET_PATH":    "Bouncer integration features may not work",
	}

	if impact, ok := impacts[envVar]; ok {
		return impact
	}
	return "Some features may not work correctly"
}
