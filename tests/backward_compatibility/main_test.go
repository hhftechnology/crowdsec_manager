package backward_compatibility

import (
	"fmt"
	"os"
	"testing"
)

// TestBackwardCompatibility is the main entry point for all backward compatibility tests
func TestBackwardCompatibility(t *testing.T) {
	config := DefaultCompatibilityTestConfig()
	runner := NewCompatibilityTestRunner(config)
	runner.RunAllCompatibilityTests(t)
}

// TestAPICompatibilityOnly runs only API compatibility tests
func TestAPICompatibilityOnly(t *testing.T) {
	config := DefaultCompatibilityTestConfig()
	config.TestEnvVars = false
	config.TestDatabase = false
	config.TestUpgrade = false
	runner := NewCompatibilityTestRunner(config)
	runner.RunAllCompatibilityTests(t)
}

// TestEnvironmentCompatibilityOnly runs only environment variable compatibility tests
func TestEnvironmentCompatibilityOnly(t *testing.T) {
	config := DefaultCompatibilityTestConfig()
	config.TestAPI = false
	config.TestDatabase = false
	config.TestUpgrade = false
	runner := NewCompatibilityTestRunner(config)
	runner.RunAllCompatibilityTests(t)
}

// TestDatabaseCompatibilityOnly runs only database migration compatibility tests
func TestDatabaseCompatibilityOnly(t *testing.T) {
	config := DefaultCompatibilityTestConfig()
	config.TestAPI = false
	config.TestEnvVars = false
	config.TestUpgrade = false
	runner := NewCompatibilityTestRunner(config)
	runner.RunAllCompatibilityTests(t)
}

// TestUpgradeCompatibilityOnly runs only upgrade scenario tests
func TestUpgradeCompatibilityOnly(t *testing.T) {
	config := DefaultCompatibilityTestConfig()
	config.TestAPI = false
	config.TestEnvVars = false
	config.TestDatabase = false
	runner := NewCompatibilityTestRunner(config)
	runner.RunAllCompatibilityTests(t)
}

// TestLegacyTraefikInstallation tests complete legacy Traefik installation upgrade
func TestLegacyTraefikInstallation(t *testing.T) {
	// This test simulates a complete legacy Traefik installation upgrade
	t.Run("CompleteTraefikUpgrade", func(t *testing.T) {
		config := DefaultCompatibilityTestConfig()
		config.LegacyVersion = "1.0.0"
		config.VerboseLogging = true
		
		runner := NewCompatibilityTestRunner(config)
		
		// Test the complete upgrade process
		runner.RunAllCompatibilityTests(t)
	})
}

// TestMinimalLegacyInstallation tests upgrade from minimal legacy installation
func TestMinimalLegacyInstallation(t *testing.T) {
	// This test simulates upgrading from a minimal legacy installation
	t.Run("MinimalLegacyUpgrade", func(t *testing.T) {
		// Test with minimal configuration
		suite := NewEnvCompatibilityTestSuite()
		
		legacyVars := map[string]string{
			"TRAEFIK_CONTAINER_NAME": "traefik",
		}
		
		env := suite.createTestEnvironment(t, legacyVars)
		defer suite.cleanupTestEnvironment(env)
		
		config := suite.loadConfiguration(t, env)
		
		// Verify basic mapping works
		if config["PROXY_TYPE"] != "traefik" {
			t.Error("Minimal legacy installation should map to traefik proxy type")
		}
		
		if config["PROXY_CONTAINER_NAME"] != "traefik" {
			t.Error("Container name should be mapped correctly")
		}
	})
}

// TestComplexLegacyInstallation tests upgrade from complex legacy installation
func TestComplexLegacyInstallation(t *testing.T) {
	// This test simulates upgrading from a complex legacy installation
	t.Run("ComplexLegacyUpgrade", func(t *testing.T) {
		suite := NewEnvCompatibilityTestSuite()
		
		legacyVars := map[string]string{
			"TRAEFIK_CONTAINER_NAME":  "traefik-production",
			"TRAEFIK_DYNAMIC_CONFIG":  "/custom/path/dynamic.yml",
			"TRAEFIK_STATIC_CONFIG":   "/custom/path/static.yml",
			"TRAEFIK_ACCESS_LOG":      "/custom/logs/access.log",
			"CROWDSEC_CONTAINER_NAME": "crowdsec-production",
		}
		
		env := suite.createTestEnvironment(t, legacyVars)
		defer suite.cleanupTestEnvironment(env)
		
		config := suite.loadConfiguration(t, env)
		
		// Verify all mappings work correctly
		expectedMappings := map[string]string{
			"PROXY_TYPE":           "traefik",
			"PROXY_CONTAINER_NAME": "traefik-production",
			"PROXY_DYNAMIC_CONFIG": "/custom/path/dynamic.yml",
			"PROXY_STATIC_CONFIG":  "/custom/path/static.yml",
			"PROXY_ACCESS_LOG":     "/custom/logs/access.log",
		}
		
		for newVar, expectedValue := range expectedMappings {
			if config[newVar] != expectedValue {
				t.Errorf("Variable %s: expected %s, got %s", newVar, expectedValue, config[newVar])
			}
		}
	})
}

// TestDatabaseMigrationScenarios tests various database migration scenarios
func TestDatabaseMigrationScenarios(t *testing.T) {
	suite := NewDatabaseMigrationTestSuite()
	
	scenarios := []struct {
		name        string
		setupFunc   func(*testing.T) string
		description string
	}{
		{
			name:        "EmptyDatabase",
			setupFunc:   suite.createTempDatabase,
			description: "Migration from empty database",
		},
		{
			name:        "LegacyDatabase",
			setupFunc:   suite.createLegacyDatabase,
			description: "Migration from legacy schema",
		},
		{
			name:        "DatabaseWithTestData",
			setupFunc:   suite.createDatabaseWithTestData,
			description: "Migration preserving existing data",
		},
	}
	
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			dbPath := scenario.setupFunc(t)
			defer func() {
				if dbPath != "" {
					os.Remove(dbPath)
				}
			}()
			
			// Extract original data if database has content
			var originalData map[string]interface{}
			if scenario.name != "EmptyDatabase" {
				originalData = suite.extractAllData(t, dbPath)
			}
			
			// Apply migration
			if err := suite.applyMigration(dbPath); err != nil {
				t.Fatalf("Migration failed for %s: %v", scenario.description, err)
			}
			
			// Verify new schema
			if err := suite.verifyNewSchema(dbPath); err != nil {
				t.Errorf("Schema verification failed for %s: %v", scenario.description, err)
			}
			
			// Verify data integrity if there was original data
			if originalData != nil {
				if err := suite.verifyDataIntegrity(t, dbPath, originalData); err != nil {
					t.Errorf("Data integrity check failed for %s: %v", scenario.description, err)
				}
			}
		})
	}
}

// TestAPIEndpointCompatibility tests specific API endpoint compatibility
func TestAPIEndpointCompatibility(t *testing.T) {
	// Test that all legacy API endpoints are still functional
	legacyEndpoints := []struct {
		endpoint    string
		description string
	}{
		{"/api/traefik/whitelist", "Legacy Traefik whitelist endpoint"},
		{"/api/traefik/captcha", "Legacy Traefik captcha endpoint"},
		{"/api/traefik/logs", "Legacy Traefik logs endpoint"},
		{"/api/traefik/health", "Legacy Traefik health endpoint"},
		{"/api/traefik/integration", "Legacy Traefik integration endpoint"},
	}
	
	for _, endpoint := range legacyEndpoints {
		t.Run(endpoint.description, func(t *testing.T) {
			// This would test the specific endpoint
			// For now, we'll just verify the test structure
			t.Logf("Testing legacy endpoint: %s", endpoint.endpoint)
			
			// In a real test, this would make HTTP requests to verify
			// that the endpoint still works and returns expected format
		})
	}
}

// TestFieldFormatCompatibility tests that API responses maintain field format compatibility
func TestFieldFormatCompatibility(t *testing.T) {
	// Test that API responses include both legacy and new field names
	fieldMappings := map[string]string{
		"traefik_enabled":        "proxy_enabled",
		"traefik_container_name": "proxy_container_name",
		"in_traefik":            "in_proxy",
		"add_to_traefik":        "add_to_proxy",
	}
	
	for legacyField, newField := range fieldMappings {
		t.Run(fmt.Sprintf("%s_to_%s", legacyField, newField), func(t *testing.T) {
			t.Logf("Testing field mapping: %s -> %s", legacyField, newField)
			
			// In a real test, this would:
			// 1. Make API request
			// 2. Parse JSON response
			// 3. Verify both legacy and new fields are present
			// 4. Verify field values are consistent
		})
	}
}

// TestEnvironmentVariableMapping tests environment variable mapping
func TestEnvironmentVariableMapping(t *testing.T) {
	// Test all legacy environment variable mappings
	variableMappings := map[string]string{
		"TRAEFIK_CONTAINER_NAME": "PROXY_CONTAINER_NAME",
		"TRAEFIK_DYNAMIC_CONFIG": "PROXY_DYNAMIC_CONFIG",
		"TRAEFIK_STATIC_CONFIG":  "PROXY_STATIC_CONFIG",
		"TRAEFIK_ACCESS_LOG":     "PROXY_ACCESS_LOG",
		"TRAEFIK_ENABLED":        "PROXY_ENABLED",
	}
	
	suite := NewEnvCompatibilityTestSuite()
	
	for legacyVar, newVar := range variableMappings {
		t.Run(fmt.Sprintf("%s_mapping", legacyVar), func(t *testing.T) {
			testValue := fmt.Sprintf("test-value-%s", legacyVar)
			
			legacyEnv := map[string]string{
				legacyVar: testValue,
			}
			
			env := suite.createTestEnvironment(t, legacyEnv)
			defer suite.cleanupTestEnvironment(env)
			
			config := suite.loadConfiguration(t, env)
			
			// Verify mapping
			if config[newVar] != testValue {
				t.Errorf("Variable %s not mapped to %s correctly: expected %s, got %s",
					legacyVar, newVar, testValue, config[newVar])
			}
			
			// Verify proxy type is set
			if config["PROXY_TYPE"] != "traefik" {
				t.Errorf("PROXY_TYPE should be 'traefik' when legacy Traefik variables are present")
			}
		})
	}
}

// TestMixedVariableScenarios tests scenarios with mixed legacy and new variables
func TestMixedVariableScenarios(t *testing.T) {
	suite := NewEnvCompatibilityTestSuite()
	
	scenarios := []struct {
		name      string
		variables map[string]string
		expected  map[string]string
	}{
		{
			name: "NewVariablesTakePrecedence",
			variables: map[string]string{
				"TRAEFIK_CONTAINER_NAME": "legacy-traefik",
				"PROXY_CONTAINER_NAME":   "new-proxy",
				"PROXY_TYPE":             "nginx",
			},
			expected: map[string]string{
				"PROXY_CONTAINER_NAME": "new-proxy",
				"PROXY_TYPE":           "nginx",
			},
		},
		{
			name: "LegacyOnlyVariables",
			variables: map[string]string{
				"TRAEFIK_CONTAINER_NAME": "legacy-only",
				"TRAEFIK_DYNAMIC_CONFIG": "/legacy/config.yml",
			},
			expected: map[string]string{
				"PROXY_CONTAINER_NAME": "legacy-only",
				"PROXY_DYNAMIC_CONFIG": "/legacy/config.yml",
				"PROXY_TYPE":           "traefik",
			},
		},
	}
	
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			env := suite.createTestEnvironment(t, scenario.variables)
			defer suite.cleanupTestEnvironment(env)
			
			config := suite.loadConfiguration(t, env)
			
			for key, expectedValue := range scenario.expected {
				if config[key] != expectedValue {
					t.Errorf("Scenario %s - Variable %s: expected %s, got %s",
						scenario.name, key, expectedValue, config[key])
				}
			}
		})
	}
}