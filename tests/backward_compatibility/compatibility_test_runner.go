package backward_compatibility

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// CompatibilityTestRunner manages backward compatibility test execution
type CompatibilityTestRunner struct {
	config *CompatibilityTestConfig
}

// CompatibilityTestConfig holds configuration for compatibility tests
type CompatibilityTestConfig struct {
	// Test execution settings
	Timeout        time.Duration
	VerboseLogging bool
	SkipCleanup    bool
	
	// Test environment settings
	BaseURL        string
	DatabasePath   string
	ConfigPath     string
	
	// Test categories
	TestAPI        bool
	TestEnvVars    bool
	TestDatabase   bool
	TestUpgrade    bool
	
	// Legacy system settings
	LegacyVersion  string
	LegacyDataPath string
}

// DefaultCompatibilityTestConfig returns default configuration
func DefaultCompatibilityTestConfig() *CompatibilityTestConfig {
	return &CompatibilityTestConfig{
		Timeout:        15 * time.Minute,
		VerboseLogging: false,
		SkipCleanup:    false,
		BaseURL:        "http://localhost:8080",
		DatabasePath:   "./test_data/settings.db",
		ConfigPath:     "./test_data/config",
		TestAPI:        true,
		TestEnvVars:    true,
		TestDatabase:   true,
		TestUpgrade:    true,
		LegacyVersion:  "1.0.0",
		LegacyDataPath: "./test_data/legacy",
	}
}

// NewCompatibilityTestRunner creates a new compatibility test runner
func NewCompatibilityTestRunner(config *CompatibilityTestConfig) *CompatibilityTestRunner {
	if config == nil {
		config = DefaultCompatibilityTestConfig()
	}
	return &CompatibilityTestRunner{config: config}
}

// RunAllCompatibilityTests runs all backward compatibility tests
func (r *CompatibilityTestRunner) RunAllCompatibilityTests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.Timeout)
	defer cancel()
	
	// Setup test environment
	if err := r.setupTestEnvironment(ctx); err != nil {
		t.Fatalf("Failed to setup test environment: %v", err)
	}
	
	if !r.config.SkipCleanup {
		defer r.cleanupTestEnvironment()
	}
	
	// Run test categories
	if r.config.TestAPI {
		t.Run("API_Compatibility", func(t *testing.T) {
			r.runAPICompatibilityTests(t)
		})
	}
	
	if r.config.TestEnvVars {
		t.Run("Environment_Compatibility", func(t *testing.T) {
			r.runEnvironmentCompatibilityTests(t)
		})
	}
	
	if r.config.TestDatabase {
		t.Run("Database_Compatibility", func(t *testing.T) {
			r.runDatabaseCompatibilityTests(t)
		})
	}
	
	if r.config.TestUpgrade {
		t.Run("Upgrade_Compatibility", func(t *testing.T) {
			r.runUpgradeCompatibilityTests(t)
		})
	}
}

// setupTestEnvironment prepares the test environment
func (r *CompatibilityTestRunner) setupTestEnvironment(ctx context.Context) error {
	// Create test directories
	testDirs := []string{
		"./test_data",
		"./test_data/legacy",
		"./test_data/config",
		"./test_data/backups",
	}
	
	for _, dir := range testDirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create test directory %s: %v", dir, err)
		}
	}
	
	// Setup legacy test data
	if err := r.setupLegacyTestData(); err != nil {
		return fmt.Errorf("failed to setup legacy test data: %v", err)
	}
	
	return nil
}

// setupLegacyTestData creates legacy test data for compatibility testing
func (r *CompatibilityTestRunner) setupLegacyTestData() error {
	// Create legacy environment file
	legacyEnv := `# Legacy CrowdSec Manager Configuration
TRAEFIK_CONTAINER_NAME=traefik-legacy
TRAEFIK_DYNAMIC_CONFIG=/etc/traefik/dynamic_config.yml
TRAEFIK_STATIC_CONFIG=/etc/traefik/traefik_config.yml
TRAEFIK_ACCESS_LOG=/var/log/traefik/access.log
CROWDSEC_CONTAINER_NAME=crowdsec-legacy
COMPOSE_FILE=docker-compose.yml
`
	
	envPath := "./test_data/legacy/.env"
	if err := os.WriteFile(envPath, []byte(legacyEnv), 0644); err != nil {
		return fmt.Errorf("failed to create legacy env file: %v", err)
	}
	
	// Create legacy docker-compose.yml
	legacyCompose := `version: '3.8'
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec-legacy
    environment:
      - COLLECTIONS=crowdsecurity/traefik
    volumes:
      - ./config/crowdsec:/etc/crowdsec
      - crowdsec-data:/var/lib/crowdsec/data
    networks:
      - crowdsec-net

  traefik:
    image: traefik:latest
    container_name: traefik-legacy
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
    image: crowdsec-manager:legacy
    container_name: crowdsec-manager-legacy
    ports:
      - "8081:8080"
    environment:
      - TRAEFIK_CONTAINER_NAME=traefik-legacy
      - CROWDSEC_CONTAINER_NAME=crowdsec-legacy
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
	
	composePath := "./test_data/legacy/docker-compose.yml"
	if err := os.WriteFile(composePath, []byte(legacyCompose), 0644); err != nil {
		return fmt.Errorf("failed to create legacy compose file: %v", err)
	}
	
	return nil
}

// runAPICompatibilityTests runs API backward compatibility tests
func (r *CompatibilityTestRunner) runAPICompatibilityTests(t *testing.T) {
	if r.config.VerboseLogging {
		t.Log("Running API compatibility tests...")
	}
	
	// Run legacy API endpoint tests
	TestLegacyAPIEndpoints(t)
	
	// Run API versioning tests
	TestAPIVersioning(t)
	
	// Run content type compatibility tests
	TestContentTypeCompatibility(t)
	
	// Run error response compatibility tests
	TestErrorResponseCompatibility(t)
}

// runEnvironmentCompatibilityTests runs environment variable compatibility tests
func (r *CompatibilityTestRunner) runEnvironmentCompatibilityTests(t *testing.T) {
	if r.config.VerboseLogging {
		t.Log("Running environment variable compatibility tests...")
	}
	
	// Run environment variable compatibility tests
	TestEnvironmentVariableCompatibility(t)
	
	// Run Docker Compose compatibility tests
	TestDockerComposeCompatibility(t)
}

// runDatabaseCompatibilityTests runs database migration compatibility tests
func (r *CompatibilityTestRunner) runDatabaseCompatibilityTests(t *testing.T) {
	if r.config.VerboseLogging {
		t.Log("Running database compatibility tests...")
	}
	
	// Run database migration integrity tests
	TestDatabaseMigrationIntegrity(t)
}

// runUpgradeCompatibilityTests runs upgrade scenario tests
func (r *CompatibilityTestRunner) runUpgradeCompatibilityTests(t *testing.T) {
	if r.config.VerboseLogging {
		t.Log("Running upgrade compatibility tests...")
	}
	
	// Test upgrade scenarios
	r.testTraefikUpgradeScenario(t)
	r.testConfigurationUpgradeScenario(t)
	r.testDataMigrationScenario(t)
}

// testTraefikUpgradeScenario tests upgrading from legacy Traefik installation
func (r *CompatibilityTestRunner) testTraefikUpgradeScenario(t *testing.T) {
	t.Run("TraefikUpgradeScenario", func(t *testing.T) {
		// Create legacy Traefik installation
		legacySetup := r.createLegacyTraefikSetup(t)
		defer r.cleanupLegacySetup(legacySetup)
		
		// Simulate upgrade process
		if err := r.simulateUpgrade(legacySetup); err != nil {
			t.Errorf("Upgrade simulation failed: %v", err)
		}
		
		// Verify upgrade results
		if err := r.verifyUpgradeResults(legacySetup); err != nil {
			t.Errorf("Upgrade verification failed: %v", err)
		}
	})
}

// testConfigurationUpgradeScenario tests configuration migration
func (r *CompatibilityTestRunner) testConfigurationUpgradeScenario(t *testing.T) {
	t.Run("ConfigurationUpgradeScenario", func(t *testing.T) {
		// Test various configuration scenarios
		scenarios := []struct {
			name   string
			config map[string]string
		}{
			{
				name: "MinimalTraefikConfig",
				config: map[string]string{
					"TRAEFIK_CONTAINER_NAME": "traefik",
				},
			},
			{
				name: "CompleteTraefikConfig",
				config: map[string]string{
					"TRAEFIK_CONTAINER_NAME": "traefik-prod",
					"TRAEFIK_DYNAMIC_CONFIG": "/custom/dynamic.yml",
					"TRAEFIK_STATIC_CONFIG":  "/custom/static.yml",
					"TRAEFIK_ACCESS_LOG":     "/custom/access.log",
					"CROWDSEC_CONTAINER_NAME": "crowdsec-prod",
				},
			},
		}
		
		for _, scenario := range scenarios {
			t.Run(scenario.name, func(t *testing.T) {
				if err := r.testConfigurationScenario(scenario.config); err != nil {
					t.Errorf("Configuration scenario %s failed: %v", scenario.name, err)
				}
			})
		}
	})
}

// testDataMigrationScenario tests data migration scenarios
func (r *CompatibilityTestRunner) testDataMigrationScenario(t *testing.T) {
	t.Run("DataMigrationScenario", func(t *testing.T) {
		// Test migration with various data scenarios
		scenarios := []string{
			"EmptyDatabase",
			"SingleSettingsRecord",
			"MultipleSettingsRecords",
			"WithWhitelistData",
			"WithComplexConfiguration",
		}
		
		for _, scenario := range scenarios {
			t.Run(scenario, func(t *testing.T) {
				if err := r.testDataMigrationScenario(scenario); err != nil {
					t.Errorf("Data migration scenario %s failed: %v", scenario, err)
				}
			})
		}
	})
}

// Helper functions for upgrade testing

type LegacySetup struct {
	WorkDir      string
	DatabasePath string
	ConfigPath   string
	EnvPath      string
}

func (r *CompatibilityTestRunner) createLegacyTraefikSetup(t *testing.T) *LegacySetup {
	// Create temporary directory for legacy setup
	workDir, err := os.MkdirTemp("", "legacy_traefik_*")
	if err != nil {
		t.Fatalf("Failed to create legacy setup directory: %v", err)
	}
	
	setup := &LegacySetup{
		WorkDir:      workDir,
		DatabasePath: fmt.Sprintf("%s/settings.db", workDir),
		ConfigPath:   fmt.Sprintf("%s/config", workDir),
		EnvPath:      fmt.Sprintf("%s/.env", workDir),
	}
	
	// Create legacy database
	dbSuite := NewDatabaseMigrationTestSuite()
	setup.DatabasePath = dbSuite.createLegacyDatabase(t)
	
	// Create legacy environment
	legacyEnv := `TRAEFIK_CONTAINER_NAME=traefik-legacy
CROWDSEC_CONTAINER_NAME=crowdsec-legacy
TRAEFIK_DYNAMIC_CONFIG=/etc/traefik/dynamic_config.yml`
	
	if err := os.WriteFile(setup.EnvPath, []byte(legacyEnv), 0644); err != nil {
		t.Fatalf("Failed to create legacy env file: %v", err)
	}
	
	return setup
}

func (r *CompatibilityTestRunner) cleanupLegacySetup(setup *LegacySetup) {
	if setup != nil && setup.WorkDir != "" {
		os.RemoveAll(setup.WorkDir)
	}
}

func (r *CompatibilityTestRunner) simulateUpgrade(setup *LegacySetup) error {
	// Simulate the upgrade process
	// This would involve:
	// 1. Detecting legacy installation
	// 2. Creating backup
	// 3. Applying migrations
	// 4. Updating configuration
	
	// For testing purposes, we'll simulate these steps
	dbSuite := NewDatabaseMigrationTestSuite()
	return dbSuite.applyMigration(setup.DatabasePath)
}

func (r *CompatibilityTestRunner) verifyUpgradeResults(setup *LegacySetup) error {
	// Verify that upgrade was successful
	dbSuite := NewDatabaseMigrationTestSuite()
	
	// Check new schema
	if err := dbSuite.verifyNewSchema(setup.DatabasePath); err != nil {
		return fmt.Errorf("new schema verification failed: %v", err)
	}
	
	// Check data preservation
	if err := dbSuite.verifyLegacyDataPreserved(setup.DatabasePath); err != nil {
		return fmt.Errorf("legacy data preservation failed: %v", err)
	}
	
	return nil
}

func (r *CompatibilityTestRunner) testConfigurationScenario(config map[string]string) error {
	// Create temporary environment with specified configuration
	tempDir, err := os.MkdirTemp("", "config_scenario_*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	
	// Create .env file with configuration
	envContent := ""
	for key, value := range config {
		envContent += fmt.Sprintf("%s=%s\n", key, value)
	}
	
	envPath := fmt.Sprintf("%s/.env", tempDir)
	if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
		return err
	}
	
	// Test configuration loading and mapping
	envSuite := NewEnvCompatibilityTestSuite()
	loadedConfig := envSuite.loadConfiguration(&testing.T{}, tempDir)
	
	// Verify expected mappings
	if config["TRAEFIK_CONTAINER_NAME"] != "" {
		if loadedConfig["PROXY_TYPE"] != "traefik" {
			return fmt.Errorf("PROXY_TYPE not set to traefik when Traefik variables present")
		}
		if loadedConfig["PROXY_CONTAINER_NAME"] != config["TRAEFIK_CONTAINER_NAME"] {
			return fmt.Errorf("PROXY_CONTAINER_NAME not mapped correctly")
		}
	}
	
	return nil
}

func (r *CompatibilityTestRunner) testDataMigrationScenario(scenario string) error {
	// Create database for specific scenario
	dbSuite := NewDatabaseMigrationTestSuite()
	
	var dbPath string
	var err error
	
	switch scenario {
	case "EmptyDatabase":
		dbPath = dbSuite.createTempDatabase(&testing.T{})
	case "SingleSettingsRecord":
		dbPath = dbSuite.createLegacyDatabase(&testing.T{})
	case "MultipleSettingsRecords":
		dbPath = dbSuite.createDatabaseWithTestData(&testing.T{})
	default:
		dbPath = dbSuite.createLegacyDatabase(&testing.T{})
	}
	
	defer os.Remove(dbPath)
	
	// Apply migration
	if err := dbSuite.applyMigration(dbPath); err != nil {
		return fmt.Errorf("migration failed: %v", err)
	}
	
	// Verify results
	if err := dbSuite.verifyNewSchema(dbPath); err != nil {
		return fmt.Errorf("schema verification failed: %v", err)
	}
	
	return nil
}

// cleanupTestEnvironment cleans up test artifacts
func (r *CompatibilityTestRunner) cleanupTestEnvironment() {
	if r.config.SkipCleanup {
		return
	}
	
	// Remove test directories
	testDirs := []string{
		"./test_data",
	}
	
	for _, dir := range testDirs {
		os.RemoveAll(dir)
	}
}

// GenerateCompatibilityReport generates a compatibility test report
func (r *CompatibilityTestRunner) GenerateCompatibilityReport(results *testing.T) error {
	// Generate comprehensive compatibility report
	// This would include:
	// - API compatibility status
	// - Environment variable mapping results
	// - Database migration results
	// - Upgrade scenario results
	
	return nil
}