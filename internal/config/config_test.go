package config

import (
	"os"
	"testing"

	"pgregory.net/rapid"
)

// **Feature: multi-proxy-architecture, Property 1: Backward Compatibility Preservation**
// **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 12.1, 12.2, 12.3, 12.4, 12.5**
func TestBackwardCompatibilityPreservation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Save original environment
		originalEnv := make(map[string]string)
		envVars := []string{
			"PROXY_TYPE", "PROXY_ENABLED", "PROXY_CONTAINER_NAME",
			"TRAEFIK_CONTAINER_NAME", "TRAEFIK_DYNAMIC_CONFIG", "TRAEFIK_STATIC_CONFIG",
			"NGINX_CONTAINER_NAME", "CADDY_CONTAINER_NAME", "HAPROXY_CONTAINER_NAME",
			"ZORAXY_CONTAINER_NAME", "COMPOSE_MODE",
		}
		
		for _, env := range envVars {
			originalEnv[env] = os.Getenv(env)
			os.Unsetenv(env)
		}
		
		defer func() {
			// Restore original environment
			for env, value := range originalEnv {
				if value != "" {
					os.Setenv(env, value)
				} else {
					os.Unsetenv(env)
				}
			}
		}()

		// Generate random legacy Traefik configuration
		traefikContainer := rapid.StringMatching(`^[a-zA-Z][a-zA-Z0-9_-]*$`).Draw(t, "traefikContainer")
		dynamicConfig := rapid.StringMatching(`^/[a-zA-Z0-9/_.-]+\.yml$`).Draw(t, "dynamicConfig")
		staticConfig := rapid.StringMatching(`^/[a-zA-Z0-9/_.-]+\.yml$`).Draw(t, "staticConfig")

		// Test Case 1: Legacy Traefik environment variables should be detected
		os.Setenv("TRAEFIK_CONTAINER_NAME", traefikContainer)
		os.Setenv("TRAEFIK_DYNAMIC_CONFIG", dynamicConfig)
		os.Setenv("TRAEFIK_STATIC_CONFIG", staticConfig)

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Failed to load config with legacy Traefik vars: %v", err)
		}

		// Property 1: Legacy Traefik installation should be auto-detected as traefik proxy type
		if cfg.ProxyType != "traefik" {
			t.Errorf("Expected proxy type 'traefik' for legacy installation, got %s", cfg.ProxyType)
		}

		// Property 2: Legacy container name should be mapped to proxy container name
		if cfg.ProxyContainerName != traefikContainer {
			t.Errorf("Expected proxy container name %s, got %s", traefikContainer, cfg.ProxyContainerName)
		}

		// Property 3: Legacy configuration paths should be preserved
		if cfg.TraefikDynamicConfig != dynamicConfig {
			t.Errorf("Expected dynamic config %s, got %s", dynamicConfig, cfg.TraefikDynamicConfig)
		}
		if cfg.TraefikStaticConfig != staticConfig {
			t.Errorf("Expected static config %s, got %s", staticConfig, cfg.TraefikStaticConfig)
		}

		// Property 4: IsLegacyTraefikInstallation should return true
		if !cfg.IsLegacyTraefikInstallation() {
			t.Error("IsLegacyTraefikInstallation should return true for legacy setup")
		}

		// Clear environment for next test
		for _, env := range envVars {
			os.Unsetenv(env)
		}

		// Test Case 2: Explicit proxy type should override auto-detection
		explicitProxyType := rapid.SampledFrom([]string{
			"traefik", "nginx", "caddy", "haproxy", "zoraxy", "standalone",
		}).Draw(t, "explicitProxyType")
		
		os.Setenv("PROXY_TYPE", explicitProxyType)
		os.Setenv("TRAEFIK_CONTAINER_NAME", traefikContainer) // This should be ignored

		cfg2, err := Load()
		if err != nil {
			t.Fatalf("Failed to load config with explicit proxy type: %v", err)
		}

		// Property 5: Explicit PROXY_TYPE should take precedence over auto-detection
		if cfg2.ProxyType != explicitProxyType {
			t.Errorf("Expected proxy type %s, got %s", explicitProxyType, cfg2.ProxyType)
		}

		// Property 6: IsLegacyTraefikInstallation should return false when PROXY_TYPE is set
		if cfg2.IsLegacyTraefikInstallation() {
			t.Error("IsLegacyTraefikInstallation should return false when PROXY_TYPE is explicitly set")
		}

		// Clear environment for next test
		for _, env := range envVars {
			os.Unsetenv(env)
		}

		// Test Case 3: No proxy configuration should default to standalone
		cfg3, err := Load()
		if err != nil {
			t.Fatalf("Failed to load config with no proxy configuration: %v", err)
		}

		// Property 7: No proxy configuration should default to standalone mode
		if cfg3.ProxyType != "standalone" {
			t.Errorf("Expected proxy type 'standalone' when no proxy configured, got %s", cfg3.ProxyType)
		}

		// Property 8: Standalone mode should have empty container name
		if cfg3.ProxyContainerName != "" {
			t.Errorf("Expected empty container name for standalone mode, got %s", cfg3.ProxyContainerName)
		}
	})
}

// Test proxy configuration generation for different proxy types
func TestProxyConfigGeneration(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random proxy type
		proxyType := rapid.SampledFrom([]string{
			"traefik", "nginx", "caddy", "haproxy", "zoraxy", "standalone",
		}).Draw(t, "proxyType")

		// Save and clear environment
		originalEnv := make(map[string]string)
		envVars := []string{
			"PROXY_TYPE", "TRAEFIK_DYNAMIC_CONFIG", "TRAEFIK_STATIC_CONFIG",
			"NGINX_LOG_PATH", "CADDY_CONFIG_PATH", "HAPROXY_CONFIG_PATH",
		}
		
		for _, env := range envVars {
			originalEnv[env] = os.Getenv(env)
			os.Unsetenv(env)
		}
		
		defer func() {
			for env, value := range originalEnv {
				if value != "" {
					os.Setenv(env, value)
				}
			}
		}()

		// Set proxy type
		os.Setenv("PROXY_TYPE", proxyType)

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Failed to load config for proxy type %s: %v", proxyType, err)
		}

		// Property: GetProxyConfig should return appropriate configuration for each proxy type
		proxyConfig := cfg.GetProxyConfig()

		switch proxyType {
		case "traefik":
			if _, exists := proxyConfig["dynamic"]; !exists {
				t.Error("Traefik config should include 'dynamic' key")
			}
			if _, exists := proxyConfig["static"]; !exists {
				t.Error("Traefik config should include 'static' key")
			}
		case "nginx":
			if _, exists := proxyConfig["log_path"]; !exists {
				t.Error("Nginx config should include 'log_path' key")
			}
		case "caddy":
			if _, exists := proxyConfig["config_path"]; !exists {
				t.Error("Caddy config should include 'config_path' key")
			}
		case "haproxy":
			if _, exists := proxyConfig["config_path"]; !exists {
				t.Error("HAProxy config should include 'config_path' key")
			}
			if _, exists := proxyConfig["socket_path"]; !exists {
				t.Error("HAProxy config should include 'socket_path' key")
			}
		case "zoraxy":
			if _, exists := proxyConfig["config_path"]; !exists {
				t.Error("Zoraxy config should include 'config_path' key")
			}
		case "standalone":
			// Standalone should have minimal or no proxy-specific config
			if len(proxyConfig) > 0 {
				t.Error("Standalone mode should have minimal proxy config")
			}
		}
	})
}

// Test environment variable validation and error handling
func TestEnvironmentVariableValidation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Save original environment
		originalProxyType := os.Getenv("PROXY_TYPE")
		defer func() {
			if originalProxyType != "" {
				os.Setenv("PROXY_TYPE", originalProxyType)
			} else {
				os.Unsetenv("PROXY_TYPE")
			}
		}()

		// Test with invalid proxy type
		invalidProxyType := rapid.StringMatching(`^[a-zA-Z]+$`).
			Filter(func(s string) bool {
				validTypes := map[string]bool{
					"traefik": true, "nginx": true, "caddy": true,
					"haproxy": true, "zoraxy": true, "standalone": true,
				}
				return !validTypes[s]
			}).Draw(t, "invalidProxyType")

		os.Setenv("PROXY_TYPE", invalidProxyType)

		cfg, err := Load()
		
		// Property: Invalid proxy types should be handled gracefully
		// The system should either return an error or default to a valid type
		if err == nil {
			// If no error, should default to a valid proxy type
			validTypes := map[string]bool{
				"traefik": true, "nginx": true, "caddy": true,
				"haproxy": true, "zoraxy": true, "standalone": true,
			}
			if !validTypes[cfg.ProxyType] {
				t.Errorf("Invalid proxy type %s should be handled gracefully", cfg.ProxyType)
			}
		}
		// If error is returned, that's also acceptable behavior
	})
}

// Test compose mode configuration
func TestComposeModeConfiguration(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Save original environment
		originalComposeMode := os.Getenv("COMPOSE_MODE")
		defer func() {
			if originalComposeMode != "" {
				os.Setenv("COMPOSE_MODE", originalComposeMode)
			} else {
				os.Unsetenv("COMPOSE_MODE")
			}
		}()

		// Test valid compose modes
		composeMode := rapid.SampledFrom([]string{"single", "separate"}).Draw(t, "composeMode")
		os.Setenv("COMPOSE_MODE", composeMode)

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Failed to load config with compose mode %s: %v", composeMode, err)
		}

		// Property: Compose mode should be set correctly
		if cfg.ComposeMode != composeMode {
			t.Errorf("Expected compose mode %s, got %s", composeMode, cfg.ComposeMode)
		}

		// Test default compose mode
		os.Unsetenv("COMPOSE_MODE")
		cfg2, err := Load()
		if err != nil {
			t.Fatalf("Failed to load config with default compose mode: %v", err)
		}

		// Property: Default compose mode should be "single"
		if cfg2.ComposeMode != "single" {
			t.Errorf("Expected default compose mode 'single', got %s", cfg2.ComposeMode)
		}
	})
}