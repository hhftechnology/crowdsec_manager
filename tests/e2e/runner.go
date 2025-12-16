package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestRunner manages end-to-end test execution
type TestRunner struct {
	config *TestConfig
}

// TestConfig holds configuration for end-to-end tests
type TestConfig struct {
	// Test execution settings
	Timeout         time.Duration
	Parallel        bool
	SkipCleanup     bool
	VerboseLogging  bool
	
	// Docker settings
	DockerRegistry  string
	ImageTag        string
	PullImages      bool
	
	// Test filters
	ProxyTypes      []string
	ComposeModes    []string
	TestCategories  []string
	
	// Performance settings
	LoadTestDuration    time.Duration
	LoadTestConcurrency int
	
	// Browser settings
	HeadlessBrowser bool
	BrowserTimeout  time.Duration
}

// DefaultTestConfig returns default test configuration
func DefaultTestConfig() *TestConfig {
	return &TestConfig{
		Timeout:             30 * time.Minute,
		Parallel:            true,
		SkipCleanup:         false,
		VerboseLogging:      false,
		DockerRegistry:      "",
		ImageTag:            "test",
		PullImages:          false,
		ProxyTypes:          []string{"traefik", "nginx", "caddy", "haproxy", "zoraxy", "standalone"},
		ComposeModes:        []string{"single", "separate"},
		TestCategories:      []string{"browser", "integration", "migration", "performance"},
		LoadTestDuration:    30 * time.Second,
		LoadTestConcurrency: 10,
		HeadlessBrowser:     true,
		BrowserTimeout:      5 * time.Minute,
	}
}

// NewTestRunner creates a new test runner
func NewTestRunner(config *TestConfig) *TestRunner {
	if config == nil {
		config = DefaultTestConfig()
	}
	return &TestRunner{config: config}
}

// RunAllTests runs all end-to-end tests
func (r *TestRunner) RunAllTests(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), r.config.Timeout)
	defer cancel()
	
	// Setup test environment
	if err := r.setupTestEnvironment(ctx); err != nil {
		t.Fatalf("Failed to setup test environment: %v", err)
	}
	
	// Run test categories
	for _, category := range r.config.TestCategories {
		t.Run(category, func(t *testing.T) {
			r.runTestCategory(t, category)
		})
	}
}

// setupTestEnvironment prepares the test environment
func (r *TestRunner) setupTestEnvironment(ctx context.Context) error {
	// Pull Docker images if requested
	if r.config.PullImages {
		if err := r.pullDockerImages(ctx); err != nil {
			return fmt.Errorf("failed to pull Docker images: %v", err)
		}
	}
	
	// Verify Docker is available
	if err := r.verifyDockerAvailable(ctx); err != nil {
		return fmt.Errorf("Docker not available: %v", err)
	}
	
	// Setup test directories
	if err := r.setupTestDirectories(); err != nil {
		return fmt.Errorf("failed to setup test directories: %v", err)
	}
	
	return nil
}

// pullDockerImages pulls required Docker images
func (r *TestRunner) pullDockerImages(ctx context.Context) error {
	images := []string{
		"crowdsecurity/crowdsec:latest",
		"traefik:latest",
		"jc21/nginx-proxy-manager:latest",
		"caddy:latest",
		"haproxy:latest",
		"zoraxydocker/zoraxy:latest",
	}
	
	// Add custom manager image
	if r.config.DockerRegistry != "" {
		images = append(images, fmt.Sprintf("%s/crowdsec-manager:%s", r.config.DockerRegistry, r.config.ImageTag))
	} else {
		images = append(images, fmt.Sprintf("crowdsec-manager:%s", r.config.ImageTag))
	}
	
	for _, image := range images {
		if r.config.VerboseLogging {
			fmt.Printf("Pulling image: %s\n", image)
		}
		// Docker pull would be implemented here
		// exec.CommandContext(ctx, "docker", "pull", image).Run()
	}
	
	return nil
}

// verifyDockerAvailable checks if Docker is available
func (r *TestRunner) verifyDockerAvailable(ctx context.Context) error {
	// Docker version check would be implemented here
	// exec.CommandContext(ctx, "docker", "version").Run()
	return nil
}

// setupTestDirectories creates necessary test directories
func (r *TestRunner) setupTestDirectories() error {
	dirs := []string{
		"tests/tmp",
		"tests/logs",
		"tests/artifacts",
	}
	
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	
	return nil
}

// runTestCategory runs tests for a specific category
func (r *TestRunner) runTestCategory(t *testing.T, category string) {
	switch category {
	case "browser":
		r.runBrowserTests(t)
	case "integration":
		r.runIntegrationTests(t)
	case "migration":
		r.runMigrationTests(t)
	case "performance":
		r.runPerformanceTests(t)
	default:
		t.Errorf("Unknown test category: %s", category)
	}
}

// runBrowserTests runs browser automation tests
func (r *TestRunner) runBrowserTests(t *testing.T) {
	if r.config.Parallel {
		t.Parallel()
	}
	
	for _, proxyType := range r.config.ProxyTypes {
		proxyType := proxyType // Capture for closure
		t.Run(fmt.Sprintf("Browser_%s", proxyType), func(t *testing.T) {
			if r.config.Parallel {
				t.Parallel()
			}
			
			env := SetupTestEnvironment(t, proxyType, "single")
			if !r.config.SkipCleanup {
				defer env.Cleanup()
			}
			
			suite := NewBrowserTestSuite(env)
			suite.testCompleteWorkflow(t)
		})
	}
	
	// Run responsive design tests
	t.Run("ResponsiveDesign", func(t *testing.T) {
		TestResponsiveDesign(t)
	})
	
	// Run accessibility tests
	t.Run("Accessibility", func(t *testing.T) {
		TestAccessibility(t)
	})
}

// runIntegrationTests runs proxy integration tests
func (r *TestRunner) runIntegrationTests(t *testing.T) {
	if r.config.Parallel {
		t.Parallel()
	}
	
	for _, proxyType := range r.config.ProxyTypes {
		for _, composeMode := range r.config.ComposeModes {
			proxyType := proxyType // Capture for closure
			composeMode := composeMode
			
			t.Run(fmt.Sprintf("Integration_%s_%s", proxyType, composeMode), func(t *testing.T) {
				if r.config.Parallel {
					t.Parallel()
				}
				
				env := SetupTestEnvironment(t, proxyType, composeMode)
				if !r.config.SkipCleanup {
					defer env.Cleanup()
				}
				
				test := NewProxyIntegrationTest(env)
				test.runProxyIntegrationTest(t)
			})
		}
	}
}

// runMigrationTests runs migration tests
func (r *TestRunner) runMigrationTests(t *testing.T) {
	// Migration tests are typically not run in parallel due to database operations
	
	t.Run("LegacyTraefikMigration", func(t *testing.T) {
		TestLegacyTraefikMigration(t)
	})
	
	t.Run("EnvironmentVariableMigration", func(t *testing.T) {
		TestEnvironmentVariableMigration(t)
	})
	
	t.Run("ConfigurationBackup", func(t *testing.T) {
		TestConfigurationBackup(t)
	})
}

// runPerformanceTests runs performance and load tests
func (r *TestRunner) runPerformanceTests(t *testing.T) {
	// Performance tests should not run in parallel to get accurate measurements
	
	t.Run("APIPerformance", func(t *testing.T) {
		TestAPIPerformance(t)
	})
	
	t.Run("MemoryUsage", func(t *testing.T) {
		TestMemoryUsage(t)
	})
	
	t.Run("ConcurrentOperations", func(t *testing.T) {
		TestConcurrentProxyOperations(t)
	})
	
	t.Run("StartupPerformance", func(t *testing.T) {
		TestStartupPerformance(t)
	})
}

// GenerateTestReport generates a comprehensive test report
func (r *TestRunner) GenerateTestReport(results *testing.T) error {
	// Test report generation would be implemented here
	// This could include:
	// - Test execution summary
	// - Performance metrics
	// - Coverage reports
	// - Artifact collection
	return nil
}

// CleanupTestEnvironment cleans up test artifacts
func (r *TestRunner) CleanupTestEnvironment() error {
	if r.config.SkipCleanup {
		return nil
	}
	
	// Cleanup operations would be implemented here:
	// - Stop all test containers
	// - Remove test networks
	// - Clean up temporary files
	// - Archive test logs
	
	return nil
}

// TestMain is the entry point for running end-to-end tests
func TestMain(m *testing.M) {
	// Parse test configuration from environment variables or flags
	config := DefaultTestConfig()
	
	// Override config from environment variables
	if timeout := os.Getenv("E2E_TIMEOUT"); timeout != "" {
		if d, err := time.ParseDuration(timeout); err == nil {
			config.Timeout = d
		}
	}
	
	if os.Getenv("E2E_PARALLEL") == "false" {
		config.Parallel = false
	}
	
	if os.Getenv("E2E_SKIP_CLEANUP") == "true" {
		config.SkipCleanup = true
	}
	
	if os.Getenv("E2E_VERBOSE") == "true" {
		config.VerboseLogging = true
	}
	
	// Create test runner
	runner := NewTestRunner(config)
	
	// Setup test environment
	ctx := context.Background()
	if err := runner.setupTestEnvironment(ctx); err != nil {
		fmt.Printf("Failed to setup test environment: %v\n", err)
		os.Exit(1)
	}
	
	// Run tests
	code := m.Run()
	
	// Cleanup
	if err := runner.CleanupTestEnvironment(); err != nil {
		fmt.Printf("Failed to cleanup test environment: %v\n", err)
	}
	
	os.Exit(code)
}