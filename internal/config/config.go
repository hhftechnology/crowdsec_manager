package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	// Server configuration
	Port        int
	Environment string
	LogLevel    string
	LogFile     string

	// Docker configuration
	DockerHost  string
	DockerHosts string // Multi-host format: "id:endpoint,id:endpoint"
	ConfigDir   string

	// Database
	DatabasePath        string
	HistoryDatabasePath string

	// CrowdSec container-internal paths and URLs
	CrowdSecScenariosDir string
	CrowdSecMetricsURL   string
	CrowdSecConsoleURL   string

	// Container names
	CrowdsecContainerName string

	// Services
	Services             []string
	ServicesWithCrowdsec []string
	IncludeCrowdsec      bool

	// CrowdSec list limits (0 = unlimited)
	DecisionListLimit int
	AlertListLimit    int

	// NATS Messaging (optional)
	NatsURL     string
	NatsToken   string
	NatsEnabled bool

	// Timeouts
	ShutdownTimeout time.Duration
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
}

// Load loads and validates application configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		Port:                  getEnvAsInt("PORT", 8080),
		Environment:           getEnv("ENVIRONMENT", "development"),
		LogLevel:              getEnv("LOG_LEVEL", "info"),
		LogFile:               getEnv("LOG_FILE", "./logs/crowdsec-manager.log"),
		DockerHost:            getEnv("DOCKER_HOST", ""),
		DockerHosts:           getEnv("DOCKER_HOSTS", ""),
		ConfigDir:             getEnv("CONFIG_DIR", "./config"),
		DatabasePath:          getEnv("DATABASE_PATH", "./data/settings.db"),
		HistoryDatabasePath:   getEnv("HISTORY_DATABASE_PATH", "./data/history.db"),
		CrowdSecScenariosDir:  getEnv("CROWDSEC_SCENARIOS_DIR", "/etc/crowdsec/scenarios"),
		CrowdSecMetricsURL:    getEnv("CROWDSEC_METRICS_URL", "http://localhost:6060/metrics"),
		CrowdSecConsoleURL:    getEnv("CROWDSEC_CONSOLE_URL", "https://app.crowdsec.net/"),
		CrowdsecContainerName: getEnv("CROWDSEC_CONTAINER_NAME", "crowdsec"),
		IncludeCrowdsec:       getEnvAsBool("INCLUDE_CROWDSEC", true),
		DecisionListLimit:     getEnvAsInt("DECISION_LIST_LIMIT", 200),
		AlertListLimit:        getEnvAsInt("ALERT_LIST_LIMIT", 200),
		NatsURL:               getEnv("NATS_URL", ""),
		NatsToken:             getEnv("NATS_TOKEN", ""),
		NatsEnabled:           getEnvAsBool("NATS_ENABLED", false),
		ShutdownTimeout:       time.Duration(getEnvAsInt("SHUTDOWN_TIMEOUT", 30)) * time.Second,
		ReadTimeout:           time.Duration(getEnvAsInt("READ_TIMEOUT", 15)) * time.Second,
		WriteTimeout:          time.Duration(getEnvAsInt("WRITE_TIMEOUT", 15)) * time.Second,
	}

	// CrowdSec-only service discovery.
	cfg.Services = []string{}
	cfg.ServicesWithCrowdsec = []string{cfg.CrowdsecContainerName}

	if err := cfg.createDirectories(); err != nil {
		return nil, fmt.Errorf("failed to create directories: %w", err)
	}

	return cfg, nil
}

// createDirectories ensures required application directories exist with proper permissions.
func (c *Config) createDirectories() error {
	dirs := []string{
		filepath.Dir(c.LogFile),
		c.ConfigDir,
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// GetServices returns the appropriate service list based on CrowdSec inclusion preference.
func (c *Config) GetServices() []string {
	if c.IncludeCrowdsec {
		return c.ServicesWithCrowdsec
	}
	return c.Services
}

// EffectiveLimit returns the effective list limit, applying the hard safety cap.
func EffectiveLimit(configured, maxLimit int) int {
	if configured <= 0 || configured > maxLimit {
		return maxLimit
	}
	return configured
}

// getEnv retrieves an environment variable or returns the default value if not set.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvAsInt retrieves an environment variable as integer or returns default if not set or invalid.
func getEnvAsInt(key string, defaultValue int) int {
	if valueStr := os.Getenv(key); valueStr != "" {
		if value, err := strconv.Atoi(valueStr); err == nil {
			return value
		}
	}
	return defaultValue
}

// getEnvAsBool retrieves an environment variable as boolean or returns default if not set or invalid.
func getEnvAsBool(key string, defaultValue bool) bool {
	if valueStr := os.Getenv(key); valueStr != "" {
		if value, err := strconv.ParseBool(valueStr); err == nil {
			return value
		}
	}
	return defaultValue
}
