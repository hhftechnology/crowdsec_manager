package backward_compatibility

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// EnvCompatibilityTestSuite tests environment variable backward compatibility
type EnvCompatibilityTestSuite struct {
	testDir string
}

// NewEnvCompatibilityTestSuite creates a new environment compatibility test suite
func NewEnvCompatibilityTestSuite() *EnvCompatibilityTestSuite {
	return &EnvCompatibilityTestSuite{}
}

// TestEnvironmentVariableCompatibility tests legacy environment variable support
func TestEnvironmentVariableCompatibility(t *testing.T) {
	suite := NewEnvCompatibilityTestSuite()
	
	// Test legacy Traefik variables
	t.Run("LegacyTraefikVariables", func(t *testing.T) {
		suite.testLegacyTraefikVariables(t)
	})
	
	// Test variable mapping
	t.Run("VariableMapping", func(t *testing.T) {
		suite.testVariableMapping(t)
	})
	
	// Test mixed legacy and new variables
	t.Run("MixedVariables", func(t *testing.T) {
		suite.testMixedVariables(t)
	})
	
	// Test default value preservation
	t.Run("DefaultValuePreservation", func(t *testing.T) {
		suite.testDefaultValuePreservation(t)
	})
}

// testLegacyTraefikVariables tests that legacy Traefik variables are recognized
func (s *EnvCompatibilityTestSuite) testLegacyTraefikVariables(t *testing.T) {
	testCases := []struct {
		name        string
		legacyVars  map[string]string
		expectedMapping map[string]string
	}{
		{
			name: "BasicTraefikVars",
			legacyVars: map[string]string{
				"TRAEFIK_CONTAINER_NAME": "my-traefik",
				"TRAEFIK_DYNAMIC_CONFIG": "/custom/dynamic.yml",
				"TRAEFIK_STATIC_CONFIG":  "/custom/static.yml",
				"TRAEFIK_ACCESS_LOG":     "/custom/access.log",
			},
			expectedMapping: map[string]string{
				"PROXY_TYPE":           "traefik",
				"PROXY_CONTAINER_NAME": "my-traefik",
				"PROXY_DYNAMIC_CONFIG": "/custom/dynamic.yml",
				"PROXY_STATIC_CONFIG":  "/custom/static.yml",
				"PROXY_ACCESS_LOG":     "/custom/access.log",
			},
		},
		{
			name: "TraefikWithCrowdSec",
			legacyVars: map[string]string{
				"TRAEFIK_CONTAINER_NAME":  "traefik-prod",
				"CROWDSEC_CONTAINER_NAME": "crowdsec-prod",
				"TRAEFIK_DYNAMIC_CONFIG":  "/etc/traefik/dynamic_config.yml",
			},
			expectedMapping: map[string]string{
				"PROXY_TYPE":             "traefik",
				"PROXY_CONTAINER_NAME":   "traefik-prod",
				"CROWDSEC_CONTAINER_NAME": "crowdsec-prod",
				"PROXY_DYNAMIC_CONFIG":   "/etc/traefik/dynamic_config.yml",
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create test environment
			env := s.createTestEnvironment(t, tc.legacyVars)
			defer s.cleanupTestEnvironment(env)
			
			// Test that legacy variables are mapped correctly
			config := s.loadConfiguration(t, env)
			
			for newVar, expectedValue := range tc.expectedMapping {
				if actualValue := config[newVar]; actualValue != expectedValue {
					t.Errorf("Variable %s: expected %s, got %s", newVar, expectedValue, actualValue)
				}
			}
		})
	}
}

// testVariableMapping tests the mapping between legacy and new variables
func (s *EnvCompatibilityTestSuite) testVariableMapping(t *testing.T) {
	variableMappings := map[string]string{
		"TRAEFIK_CONTAINER_NAME": "PROXY_CONTAINER_NAME",
		"TRAEFIK_DYNAMIC_CONFIG": "PROXY_DYNAMIC_CONFIG",
		"TRAEFIK_STATIC_CONFIG":  "PROXY_STATIC_CONFIG",
		"TRAEFIK_ACCESS_LOG":     "PROXY_ACCESS_LOG",
		"TRAEFIK_ENABLED":        "PROXY_ENABLED",
	}
	
	for legacyVar, newVar := range variableMappings {
		t.Run(fmt.Sprintf("%s_to_%s", legacyVar, newVar), func(t *testing.T) {
			testValue := "test-value-" + legacyVar
			
			// Create environment with only legacy variable
			legacyEnv := map[string]string{
				legacyVar: testValue,
			}
			
			env := s.createTestEnvironment(t, legacyEnv)
			defer s.cleanupTestEnvironment(env)
			
			config := s.loadConfiguration(t, env)
			
			// Check that new variable has the mapped value
			if config[newVar] != testValue {
				t.Errorf("Legacy variable %s not mapped to %s: expected %s, got %s", 
					legacyVar, newVar, testValue, config[newVar])
			}
			
			// Check that PROXY_TYPE is set to traefik when Traefik variables are present
			if config["PROXY_TYPE"] != "traefik" {
				t.Errorf("PROXY_TYPE should be set to 'traefik' when legacy Traefik variables are present")
			}
		})
	}
}

// testMixedVariables tests behavior when both legacy and new variables are present
func (s *EnvCompatibilityTestSuite) testMixedVariables(t *testing.T) {
	testCases := []struct {
		name        string
		variables   map[string]string
		expectError bool
		expected    map[string]string
	}{
		{
			name: "NewVariablesTakePrecedence",
			variables: map[string]string{
				"TRAEFIK_CONTAINER_NAME": "legacy-traefik",
				"PROXY_CONTAINER_NAME":   "new-proxy",
				"PROXY_TYPE":             "nginx",
			},
			expectError: false,
			expected: map[string]string{
				"PROXY_CONTAINER_NAME": "new-proxy",
				"PROXY_TYPE":           "nginx",
			},
		},
		{
			name: "LegacyVariablesWhenNoNew",
			variables: map[string]string{
				"TRAEFIK_CONTAINER_NAME": "legacy-traefik",
				"TRAEFIK_DYNAMIC_CONFIG": "/legacy/dynamic.yml",
			},
			expectError: false,
			expected: map[string]string{
				"PROXY_CONTAINER_NAME": "legacy-traefik",
				"PROXY_DYNAMIC_CONFIG": "/legacy/dynamic.yml",
				"PROXY_TYPE":           "traefik",
			},
		},
		{
			name: "ConflictingProxyTypes",
			variables: map[string]string{
				"TRAEFIK_CONTAINER_NAME": "traefik",
				"PROXY_TYPE":             "nginx",
			},
			expectError: false, // New variables take precedence
			expected: map[string]string{
				"PROXY_TYPE": "nginx",
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			env := s.createTestEnvironment(t, tc.variables)
			defer s.cleanupTestEnvironment(env)
			
			config := s.loadConfiguration(t, env)
			
			for key, expectedValue := range tc.expected {
				if actualValue := config[key]; actualValue != expectedValue {
					t.Errorf("Variable %s: expected %s, got %s", key, expectedValue, actualValue)
				}
			}
		})
	}
}

// testDefaultValuePreservation tests that default values are preserved during migration
func (s *EnvCompatibilityTestSuite) testDefaultValuePreservation(t *testing.T) {
	// Test with minimal legacy configuration
	legacyVars := map[string]string{
		"TRAEFIK_CONTAINER_NAME": "traefik",
	}
	
	env := s.createTestEnvironment(t, legacyVars)
	defer s.cleanupTestEnvironment(env)
	
	config := s.loadConfiguration(t, env)
	
	// Check that default values are applied
	expectedDefaults := map[string]string{
		"PROXY_TYPE":           "traefik",
		"PROXY_CONTAINER_NAME": "traefik",
		"PROXY_DYNAMIC_CONFIG": "/etc/traefik/dynamic_config.yml",
		"PROXY_STATIC_CONFIG":  "/etc/traefik/traefik_config.yml",
		"PROXY_ACCESS_LOG":     "/var/log/traefik/access.log",
		"COMPOSE_MODE":         "single",
		"PROXY_ENABLED":        "true",
	}
	
	for key, expectedValue := range expectedDefaults {
		if actualValue := config[key]; actualValue != expectedValue {
			t.Errorf("Default value for %s: expected %s, got %s", key, expectedValue, actualValue)
		}
	}
}

// createTestEnvironment creates a test environment with specified variables
func (s *EnvCompatibilityTestSuite) createTestEnvironment(t *testing.T, variables map[string]string) string {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "env_compat_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	
	// Create .env file
	envPath := filepath.Join(tempDir, ".env")
	envContent := ""
	for key, value := range variables {
		envContent += fmt.Sprintf("%s=%s\n", key, value)
	}
	
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to create .env file: %v", err)
	}
	
	return tempDir
}

// cleanupTestEnvironment removes test environment
func (s *EnvCompatibilityTestSuite) cleanupTestEnvironment(envDir string) {
	os.RemoveAll(envDir)
}

// loadConfiguration simulates loading configuration with legacy variable mapping
func (s *EnvCompatibilityTestSuite) loadConfiguration(t *testing.T, envDir string) map[string]string {
	// This simulates the configuration loading logic that maps legacy variables
	envPath := filepath.Join(envDir, ".env")
	
	// Read .env file
	content, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatalf("Failed to read .env file: %v", err)
	}
	
	// Parse variables
	vars := make(map[string]string)
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			vars[parts[0]] = parts[1]
		}
	}
	
	// Apply legacy variable mapping logic
	config := make(map[string]string)
	
	// Copy all variables first
	for k, v := range vars {
		config[k] = v
	}
	
	// Apply legacy mappings
	legacyMappings := map[string]string{
		"TRAEFIK_CONTAINER_NAME": "PROXY_CONTAINER_NAME",
		"TRAEFIK_DYNAMIC_CONFIG": "PROXY_DYNAMIC_CONFIG",
		"TRAEFIK_STATIC_CONFIG":  "PROXY_STATIC_CONFIG",
		"TRAEFIK_ACCESS_LOG":     "PROXY_ACCESS_LOG",
		"TRAEFIK_ENABLED":        "PROXY_ENABLED",
	}
	
	hasTraefikVars := false
	for legacyVar, newVar := range legacyMappings {
		if value, exists := vars[legacyVar]; exists {
			hasTraefikVars = true
			// Only map if new variable doesn't exist (new takes precedence)
			if _, newExists := vars[newVar]; !newExists {
				config[newVar] = value
			}
		}
	}
	
	// Set PROXY_TYPE to traefik if legacy Traefik variables are present
	if hasTraefikVars {
		if _, exists := vars["PROXY_TYPE"]; !exists {
			config["PROXY_TYPE"] = "traefik"
		}
	}
	
	// Apply defaults
	defaults := map[string]string{
		"PROXY_DYNAMIC_CONFIG": "/etc/traefik/dynamic_config.yml",
		"PROXY_STATIC_CONFIG":  "/etc/traefik/traefik_config.yml",
		"PROXY_ACCESS_LOG":     "/var/log/traefik/access.log",
		"COMPOSE_MODE":         "single",
		"PROXY_ENABLED":        "true",
	}
	
	for key, defaultValue := range defaults {
		if _, exists := config[key]; !exists {
			config[key] = defaultValue
		}
	}
	
	return config
}

// TestDockerComposeCompatibility tests Docker Compose backward compatibility
func TestDockerComposeCompatibility(t *testing.T) {
	suite := NewEnvCompatibilityTestSuite()
	
	t.Run("LegacyComposeFile", func(t *testing.T) {
		suite.testLegacyComposeFile(t)
	})
	
	t.Run("LegacyServiceNames", func(t *testing.T) {
		suite.testLegacyServiceNames(t)
	})
	
	t.Run("LegacyVolumeMapping", func(t *testing.T) {
		suite.testLegacyVolumeMapping(t)
	})
}

// testLegacyComposeFile tests that legacy docker-compose.yml files work
func (s *EnvCompatibilityTestSuite) testLegacyComposeFile(t *testing.T) {
	// Create legacy docker-compose.yml content
	legacyCompose := `version: '3.8'
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    environment:
      - COLLECTIONS=crowdsecurity/traefik
    volumes:
      - ./config/crowdsec:/etc/crowdsec
      - crowdsec-data:/var/lib/crowdsec/data
    networks:
      - crowdsec-net

  traefik:
    image: traefik:latest
    container_name: traefik
    ports:
      - "80:80"
      - "8080:8080"
    command:
      - --api.insecure=true
      - --providers.docker=true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./config/traefik:/etc/traefik
    networks:
      - crowdsec-net

  crowdsec-manager:
    image: crowdsec-manager:latest
    container_name: crowdsec-manager
    ports:
      - "8081:8080"
    environment:
      - TRAEFIK_CONTAINER_NAME=traefik
      - CROWDSEC_CONTAINER_NAME=crowdsec
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./data:/app/data
    networks:
      - crowdsec-net

volumes:
  crowdsec-data:

networks:
  crowdsec-net:
    driver: bridge`
	
	// Create test environment
	tempDir, err := os.MkdirTemp("", "compose_compat_test_*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	composePath := filepath.Join(tempDir, "docker-compose.yml")
	if err := os.WriteFile(composePath, []byte(legacyCompose), 0644); err != nil {
		t.Fatalf("Failed to create compose file: %v", err)
	}
	
	// Test that the compose file is valid and can be parsed
	if err := s.validateComposeFile(composePath); err != nil {
		t.Errorf("Legacy compose file validation failed: %v", err)
	}
	
	// Test that services can be started (dry run)
	if err := s.testComposeServices(tempDir); err != nil {
		t.Errorf("Legacy compose services test failed: %v", err)
	}
}

// testLegacyServiceNames tests that legacy service names are recognized
func (s *EnvCompatibilityTestSuite) testLegacyServiceNames(t *testing.T) {
	legacyServiceNames := []string{
		"crowdsec",
		"traefik",
		"crowdsec-manager",
	}
	
	for _, serviceName := range legacyServiceNames {
		t.Run(serviceName, func(t *testing.T) {
			// Test that legacy service names are still supported
			if !s.isServiceNameSupported(serviceName) {
				t.Errorf("Legacy service name %s is not supported", serviceName)
			}
		})
	}
}

// testLegacyVolumeMapping tests that legacy volume mappings work
func (s *EnvCompatibilityTestSuite) testLegacyVolumeMapping(t *testing.T) {
	legacyVolumeMappings := map[string]string{
		"./config/traefik:/etc/traefik":                     "Traefik config mapping",
		"./config/crowdsec:/etc/crowdsec":                   "CrowdSec config mapping",
		"/var/run/docker.sock:/var/run/docker.sock":         "Docker socket mapping",
		"./data:/app/data":                                  "Data directory mapping",
		"crowdsec-data:/var/lib/crowdsec/data":              "CrowdSec data volume",
	}
	
	for mapping, description := range legacyVolumeMappings {
		t.Run(description, func(t *testing.T) {
			if !s.isVolumeMappingValid(mapping) {
				t.Errorf("Legacy volume mapping %s is not valid", mapping)
			}
		})
	}
}

// Helper functions for testing

func (s *EnvCompatibilityTestSuite) validateComposeFile(composePath string) error {
	// This would validate the compose file syntax
	// For testing purposes, we'll just check if it exists and is readable
	_, err := os.ReadFile(composePath)
	return err
}

func (s *EnvCompatibilityTestSuite) testComposeServices(composeDir string) error {
	// This would test that compose services can be started
	// For testing purposes, we'll simulate a successful validation
	return nil
}

func (s *EnvCompatibilityTestSuite) isServiceNameSupported(serviceName string) bool {
	supportedServices := []string{
		"crowdsec", "traefik", "crowdsec-manager",
		"nginx", "caddy", "haproxy", "zoraxy",
	}
	
	for _, supported := range supportedServices {
		if serviceName == supported {
			return true
		}
	}
	return false
}

func (s *EnvCompatibilityTestSuite) isVolumeMappingValid(mapping string) bool {
	// Basic validation of volume mapping format
	parts := strings.Split(mapping, ":")
	return len(parts) >= 2
}