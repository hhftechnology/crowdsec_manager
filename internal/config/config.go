package config

import (
	"crowdsec-manager/internal/compose"
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


	// Services
	Services             []string
	ServicesWithCrowdsec []string
	IncludeCrowdsec      bool
	IncludePangolin      bool
	IncludeGerbil        bool

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
		IncludeCrowdsec:       getEnvAsBool("INCLUDE_CROWDSEC", true),
		IncludePangolin:       getEnvAsBool("INCLUDE_PANGOLIN", true),
		IncludeGerbil:         getEnvAsBool("INCLUDE_GERBIL", true),
		ShutdownTimeout:       time.Duration(getEnvAsInt("SHUTDOWN_TIMEOUT", 30)) * time.Second,
		ReadTimeout:           time.Duration(getEnvAsInt("READ_TIMEOUT", 15)) * time.Second,
		WriteTimeout:          time.Duration(getEnvAsInt("WRITE_TIMEOUT", 15)) * time.Second,
	}

	// Build services list dynamically from compose file for accurate service discovery
	if project, err := compose.LoadComposeFile(cfg.ComposeFile); err == nil {
		allServices := project.GetServiceNames()

		// Filter to known/managed services only to avoid unintended service management
		knownServices := map[string]bool{
			cfg.TraefikContainerName:  true,
			cfg.CrowdsecContainerName: true,
			cfg.PangolinContainerName: true,
			cfg.GerbilContainerName:   true,
		}

		cfg.Services = []string{}
		cfg.ServicesWithCrowdsec = []string{}

		for _, svc := range allServices {
			if knownServices[svc] {
				// Respect feature flags for optional services
				if svc == cfg.PangolinContainerName && !cfg.IncludePangolin {
					continue
				}
				if svc == cfg.GerbilContainerName && !cfg.IncludeGerbil {
					continue
				}

				// Separate services list (without CrowdSec) from full services list (with CrowdSec)
				if svc != cfg.CrowdsecContainerName {
					cfg.Services = append(cfg.Services, svc)
				}
				cfg.ServicesWithCrowdsec = append(cfg.ServicesWithCrowdsec, svc)
			}
		}
	} else {
		// Fallback to manual service list construction if compose file is unavailable or invalid
		cfg.Services = []string{cfg.TraefikContainerName}
		if cfg.IncludePangolin {
			cfg.Services = append(cfg.Services, cfg.PangolinContainerName)
		}
		if cfg.IncludeGerbil {
			cfg.Services = append(cfg.Services, cfg.GerbilContainerName)
		}

		// Pre-allocate slice for better performance
		cfg.ServicesWithCrowdsec = make([]string, len(cfg.Services))
		copy(cfg.ServicesWithCrowdsec, cfg.Services)
		cfg.ServicesWithCrowdsec = append(cfg.ServicesWithCrowdsec, cfg.CrowdsecContainerName)
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
