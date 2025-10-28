package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Config holds the application configuration
type Config struct {
	// Server configuration
	Port        int
	Environment string
	LogLevel    string
	LogFile     string

	// Docker configuration
	DockerHost         string
	ComposeFile        string
	PangolinDir        string
	ConfigDir          string

	// Database
	DatabasePath       string

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

	// Services
	Services            []string
	ServicesWithCrowdsec []string
	IncludeCrowdsec     bool

	// Timeouts
	ShutdownTimeout time.Duration
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
}

// Load loads configuration from environment variables with defaults
func Load() (*Config, error) {
	cfg := &Config{
		Port:        getEnvAsInt("PORT", 8080),
		Environment: getEnv("ENVIRONMENT", "development"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),
		LogFile:     getEnv("LOG_FILE", "./logs/crowdsec-manager.log"),

		DockerHost:         getEnv("DOCKER_HOST", ""),
		ComposeFile:        getEnv("COMPOSE_FILE", "./docker-compose.yml"),
		PangolinDir:        getEnv("PANGOLIN_DIR", "."),
		ConfigDir:          getEnv("CONFIG_DIR", "./config"),

		DatabasePath:       getEnv("DATABASE_PATH", "./data/settings.db"),

		TraefikDynamicConfig: getEnv("TRAEFIK_DYNAMIC_CONFIG", "/etc/traefik/conf/dynamic_config.yml"),
		TraefikStaticConfig:  getEnv("TRAEFIK_STATIC_CONFIG", "/etc/traefik/traefik.yml"),
		TraefikAccessLog:     getEnv("TRAEFIK_ACCESS_LOG", "/var/log/traefik/access.log"),
		TraefikErrorLog:      getEnv("TRAEFIK_ERROR_LOG", "/var/log/traefik/traefik.log"),
		CrowdSecAcquisFile:   getEnv("CROWDSEC_ACQUIS_FILE", "/etc/crowdsec/acquis.yaml"),

		BackupDir:     getEnv("BACKUP_DIR", "./backups"),
		RetentionDays: getEnvAsInt("RETENTION_DAYS", 60),
		BackupItems:   []string{"docker-compose.yml", "config"},

		Services:             []string{"pangolin", "gerbil", "traefik"},
		ServicesWithCrowdsec: []string{"pangolin", "gerbil", "crowdsec", "traefik"},
		IncludeCrowdsec:      getEnvAsBool("INCLUDE_CROWDSEC", true),

		ShutdownTimeout: time.Duration(getEnvAsInt("SHUTDOWN_TIMEOUT", 30)) * time.Second,
		ReadTimeout:     time.Duration(getEnvAsInt("READ_TIMEOUT", 15)) * time.Second,
		WriteTimeout:    time.Duration(getEnvAsInt("WRITE_TIMEOUT", 15)) * time.Second,
	}

	// Ensure required directories exist
	if err := cfg.createDirectories(); err != nil {
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	return cfg, nil
}

// createDirectories ensures all required directories exist
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

// GetServices returns the appropriate service list based on CrowdSec inclusion
func (c *Config) GetServices() []string {
	if c.IncludeCrowdsec {
		return c.ServicesWithCrowdsec
	}
	return c.Services
}

// Helper functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if valueStr := os.Getenv(key); valueStr != "" {
		if value, err := strconv.Atoi(valueStr); err == nil {
			return value
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if valueStr := os.Getenv(key); valueStr != "" {
		if value, err := strconv.ParseBool(valueStr); err == nil {
			return value
		}
	}
	return defaultValue
}
