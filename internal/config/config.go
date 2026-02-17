package config

import (
	"os"
	"strings"
)

// Config holds all application configuration loaded from environment variables.
type Config struct {
	Port              string
	ProxyType         string
	DataDir           string
	LogLevel          string
	CrowdSecContainer string
	ProxyContainer    string
	DevMode           bool
}

// Load reads configuration from environment variables with sensible defaults.
func Load() *Config {
	cfg := &Config{
		Port:              envOrDefault("PORT", "8080"),
		ProxyType:         envOrDefault("PROXY_TYPE", ""),
		DataDir:           envOrDefault("DATA_DIR", "/app/data"),
		LogLevel:          envOrDefault("LOG_LEVEL", "info"),
		CrowdSecContainer: envOrDefault("CROWDSEC_CONTAINER", "crowdsec"),
		ProxyContainer:    envOrDefault("PROXY_CONTAINER", "traefik"),
		DevMode:           envBool("DEV_MODE"),
	}
	return cfg
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func envBool(key string) bool {
	v := strings.ToLower(os.Getenv(key))
	return v == "true" || v == "1" || v == "yes"
}
