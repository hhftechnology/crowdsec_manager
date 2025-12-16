package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Config holds all application configuration loaded from environment variables with sensible defaults
type Config struct {
	// Server configuration
	Port        int
	Environment string
	LogLevel    string
	LogFile     string

	// Docker configuration
	DockerHost  string
	ComposeFile string
	PangolinDir string
	ConfigDir   string

	// Database
	DatabasePath string

	// Proxy configuration (NEW)
	ProxyType         string
	ProxyEnabled      bool
	ProxyContainerName string
	ComposeMode       string

	// File paths (from environment or database)
	TraefikDynamicConfig string
	TraefikStaticConfig  string
	TraefikAccessLog     string
	TraefikErrorLog      string
	CrowdSecAcquisFile   string

	// Backup configuration
	BackupDir     string
	RetentionDays int
	BackupItems   []string

	// Container Names
	CrowdsecContainerName string
	PangolinContainerName string
	GerbilContainerName   string
	TraefikContainerName  string

	// CrowdSec LAPI Configuration
	CrowdSecLAPIUrl       string
	CrowdSecLAPIMachineID string
	CrowdSecLAPIPassword  string

	// Services
	Services             []string
	ServicesWithCrowdsec []string
	IncludeCrowdsec      bool
	IncludePangolin      bool
	IncludeGerbil        bool

	// Add-on configuration
	PangolinEnabled bool
	GerbilEnabled   bool

	// Timeouts
	ShutdownTimeout time.Duration
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
}

// Load loads and validates application configuration from environment variables
// It also creates required directories and dynamically builds service lists from compose file
func Load() (*Config, error) {
	cfg := &Config{
		Port:                  getEnvAsInt("PORT", 8080),
		Environment:           getEnv("ENVIRONMENT", "development"),
		LogLevel:              getEnv("LOG_LEVEL", "info"),
		LogFile:               getEnv("LOG_FILE", "./logs/crowdsec-manager.log"),
		DockerHost:            getEnv("DOCKER_HOST", ""),
		ComposeFile:           getEnv("COMPOSE_FILE", "./docker-compose.yml"),
		PangolinDir:           getEnv("PANGOLIN_DIR", "."),
		ConfigDir:             getEnv("CONFIG_DIR", "./config"),
		DatabasePath:          getEnv("DATABASE_PATH", "./data/settings.db"),
		
		// Proxy configuration with backward compatibility
		ProxyType:             getEnv("PROXY_TYPE", ""),
		ProxyEnabled:          getEnvAsBool("PROXY_ENABLED", true),
		ProxyContainerName:    getEnv("PROXY_CONTAINER_NAME", ""),
		ComposeMode:           getEnv("COMPOSE_MODE", "single"),
		
		TraefikDynamicConfig:  getEnv("TRAEFIK_DYNAMIC_CONFIG", "/etc/traefik/dynamic_config.yml"),
		TraefikStaticConfig:   getEnv("TRAEFIK_STATIC_CONFIG", "/etc/traefik/traefik_config.yml"),
		TraefikAccessLog:      getEnv("TRAEFIK_ACCESS_LOG", "/var/log/traefik/access.log"),
		TraefikErrorLog:       getEnv("TRAEFIK_ERROR_LOG", "/var/log/traefik/traefik.log"),
		CrowdSecAcquisFile:    getEnv("CROWDSEC_ACQUIS_FILE", "/etc/crowdsec/acquis.yaml"),
		BackupDir:             getEnv("BACKUP_DIR", "./backups"),
		RetentionDays:         getEnvAsInt("RETENTION_DAYS", 60),
		BackupItems:           []string{"docker-compose.yml", "config"},
		CrowdsecContainerName: getEnv("CROWDSEC_CONTAINER_NAME", "crowdsec"),
		PangolinContainerName: getEnv("PANGOLIN_CONTAINER_NAME", "pangolin"),
		GerbilContainerName:   getEnv("GERBIL_CONTAINER_NAME", "gerbil"),
		TraefikContainerName:  getEnv("TRAEFIK_CONTAINER_NAME", "traefik"),
		CrowdSecLAPIUrl:       getEnv("CROWDSEC_LAPI_URL", "http://crowdsec:8080"),
		CrowdSecLAPIMachineID: getEnv("CROWDSEC_LAPI_MACHINE_ID", ""),
		CrowdSecLAPIPassword:  getEnv("CROWDSEC_LAPI_PASSWORD", ""),
		IncludeCrowdsec:       getEnvAsBool("INCLUDE_CROWDSEC", true),
		IncludePangolin:       getEnvAsBool("INCLUDE_PANGOLIN", true),
		IncludeGerbil:         getEnvAsBool("INCLUDE_GERBIL", true),
		
		// Add-on configuration
		PangolinEnabled:       getEnvAsBool("PANGOLIN_ENABLED", false),
		GerbilEnabled:         getEnvAsBool("GERBIL_ENABLED", false),
		ShutdownTimeout:       time.Duration(getEnvAsInt("SHUTDOWN_TIMEOUT", 30)) * time.Second,
		ReadTimeout:           time.Duration(getEnvAsInt("READ_TIMEOUT", 15)) * time.Second,
		WriteTimeout:          time.Duration(getEnvAsInt("WRITE_TIMEOUT", 15)) * time.Second,
	}

	// Build services list based on proxy type and enabled add-ons
	cfg.Services = []string{}
	cfg.ServicesWithCrowdsec = []string{}

	// Add proxy service based on type
	if cfg.ProxyType != "standalone" && cfg.ProxyContainerName != "" {
		cfg.Services = append(cfg.Services, cfg.ProxyContainerName)
	}

	// Add Traefik add-ons if enabled and proxy type is Traefik
	if cfg.ProxyType == "traefik" {
		if cfg.IncludePangolin && cfg.PangolinEnabled {
			cfg.Services = append(cfg.Services, cfg.PangolinContainerName)
		}
		if cfg.IncludeGerbil && cfg.GerbilEnabled {
			cfg.Services = append(cfg.Services, cfg.GerbilContainerName)
		}
	}

	// Create services list with CrowdSec
	cfg.ServicesWithCrowdsec = make([]string, len(cfg.Services))
	copy(cfg.ServicesWithCrowdsec, cfg.Services)
	cfg.ServicesWithCrowdsec = append(cfg.ServicesWithCrowdsec, cfg.CrowdsecContainerName)

	// Auto-detect proxy type from existing environment variables for backward compatibility
	if err := cfg.detectProxyType(); err != nil {
		return nil, fmt.Errorf("failed to detect proxy type: %w", err)
	}

	// Ensure required directories exist
	if err := cfg.createDirectories(); err != nil {
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	return cfg, nil
}

// createDirectories ensures all required application directories exist with proper permissions
func (c *Config) createDirectories() error {
	dirs := []string{
		filepath.Dir(c.LogFile),
		c.BackupDir,
		c.ConfigDir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// GetServices returns the appropriate service list based on CrowdSec inclusion preference
func (c *Config) GetServices() []string {
	if c.IncludeCrowdsec {
		return c.ServicesWithCrowdsec
	}
	return c.Services
}

// getEnv retrieves an environment variable or returns the default value if not set
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvAsInt retrieves an environment variable as integer or returns default if not set or invalid
func getEnvAsInt(key string, defaultValue int) int {
	if valueStr := os.Getenv(key); valueStr != "" {
		if value, err := strconv.Atoi(valueStr); err == nil {
			return value
		}
	}
	return defaultValue
}

// getEnvAsBool retrieves an environment variable as boolean or returns default if not set or invalid
// Accepts: 1, t, T, TRUE, true, True, 0, f, F, FALSE, false, False
func getEnvAsBool(key string, defaultValue bool) bool {
	if valueStr := os.Getenv(key); valueStr != "" {
		if value, err := strconv.ParseBool(valueStr); err == nil {
			return value
		}
	}
	return defaultValue
}
// detectProxyType auto-detects proxy type from existing environment variables
// Provides backward compatibility for existing Traefik installations
func (c *Config) detectProxyType() error {
	// If proxy type is explicitly set, use it
	if c.ProxyType != "" {
		return c.validateAndSetProxyConfig()
	}

	// Auto-detect from legacy environment variables
	if c.TraefikContainerName != "" || 
	   getEnv("TRAEFIK_DYNAMIC_CONFIG", "") != "" ||
	   getEnv("TRAEFIK_STATIC_CONFIG", "") != "" {
		c.ProxyType = "traefik"
		c.ProxyContainerName = c.TraefikContainerName
		return nil
	}

	// Check for other proxy types based on container names
	if nginxContainer := getEnv("NGINX_CONTAINER_NAME", ""); nginxContainer != "" {
		c.ProxyType = "nginx"
		c.ProxyContainerName = nginxContainer
		return nil
	}

	if caddyContainer := getEnv("CADDY_CONTAINER_NAME", ""); caddyContainer != "" {
		c.ProxyType = "caddy"
		c.ProxyContainerName = caddyContainer
		return nil
	}

	if haproxyContainer := getEnv("HAPROXY_CONTAINER_NAME", ""); haproxyContainer != "" {
		c.ProxyType = "haproxy"
		c.ProxyContainerName = haproxyContainer
		return nil
	}

	if zoraxyContainer := getEnv("ZORAXY_CONTAINER_NAME", ""); zoraxyContainer != "" {
		c.ProxyType = "zoraxy"
		c.ProxyContainerName = zoraxyContainer
		return nil
	}

	// Default to standalone mode if no proxy is detected
	c.ProxyType = "standalone"
	c.ProxyContainerName = ""
	return nil
}

// validateAndSetProxyConfig validates proxy configuration and sets container name
func (c *Config) validateAndSetProxyConfig() error {
	switch c.ProxyType {
	case "traefik":
		if c.ProxyContainerName == "" {
			c.ProxyContainerName = c.TraefikContainerName
		}
	case "nginx":
		if c.ProxyContainerName == "" {
			c.ProxyContainerName = getEnv("NGINX_CONTAINER_NAME", "nginx-proxy-manager")
		}
	case "caddy":
		if c.ProxyContainerName == "" {
			c.ProxyContainerName = getEnv("CADDY_CONTAINER_NAME", "caddy")
		}
	case "haproxy":
		if c.ProxyContainerName == "" {
			c.ProxyContainerName = getEnv("HAPROXY_CONTAINER_NAME", "haproxy")
		}
	case "zoraxy":
		if c.ProxyContainerName == "" {
			c.ProxyContainerName = getEnv("ZORAXY_CONTAINER_NAME", "zoraxy")
		}
	case "standalone":
		c.ProxyContainerName = ""
	default:
		return fmt.Errorf("invalid proxy type: %s", c.ProxyType)
	}
	return nil
}

// GetProxyConfig returns proxy configuration for adapter initialization
func (c *Config) GetProxyConfig() map[string]string {
	config := make(map[string]string)
	
	switch c.ProxyType {
	case "traefik":
		config["dynamic"] = c.TraefikDynamicConfig
		config["static"] = c.TraefikStaticConfig
		config["access_log"] = c.TraefikAccessLog
		config["error_log"] = c.TraefikErrorLog
	case "nginx":
		config["log_path"] = getEnv("NGINX_LOG_PATH", "/data/logs")
		config["config_path"] = getEnv("NGINX_CONFIG_PATH", "/data/nginx")
	case "caddy":
		config["config_path"] = getEnv("CADDY_CONFIG_PATH", "/etc/caddy")
		config["log_path"] = getEnv("CADDY_LOG_PATH", "/var/log/caddy")
	case "haproxy":
		config["config_path"] = getEnv("HAPROXY_CONFIG_PATH", "/usr/local/etc/haproxy")
		config["socket_path"] = getEnv("HAPROXY_SOCKET_PATH", "/var/run/haproxy.sock")
	case "zoraxy":
		config["config_path"] = getEnv("ZORAXY_CONFIG_PATH", "/opt/zoraxy")
	}
	
	return config
}

// IsLegacyTraefikInstallation checks if this is a legacy Traefik installation
func (c *Config) IsLegacyTraefikInstallation() bool {
	return c.ProxyType == "traefik" && 
		   (getEnv("PROXY_TYPE", "") == "" && c.TraefikContainerName != "")
}