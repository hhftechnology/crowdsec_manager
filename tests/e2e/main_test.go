package e2e

import (
	"testing"
)

// TestEndToEnd is the main entry point for all end-to-end tests
func TestEndToEnd(t *testing.T) {
	config := DefaultTestConfig()
	runner := NewTestRunner(config)
	runner.RunAllTests(t)
}

// TestBrowserOnly runs only browser automation tests
func TestBrowserOnly(t *testing.T) {
	config := DefaultTestConfig()
	config.TestCategories = []string{"browser"}
	runner := NewTestRunner(config)
	runner.RunAllTests(t)
}

// TestIntegrationOnly runs only integration tests
func TestIntegrationOnly(t *testing.T) {
	config := DefaultTestConfig()
	config.TestCategories = []string{"integration"}
	runner := NewTestRunner(config)
	runner.RunAllTests(t)
}

// TestMigrationOnly runs only migration tests
func TestMigrationOnly(t *testing.T) {
	config := DefaultTestConfig()
	config.TestCategories = []string{"migration"}
	runner := NewTestRunner(config)
	runner.RunAllTests(t)
}

// TestPerformanceOnly runs only performance tests
func TestPerformanceOnly(t *testing.T) {
	config := DefaultTestConfig()
	config.TestCategories = []string{"performance"}
	runner := NewTestRunner(config)
	runner.RunAllTests(t)
}

// TestTraefikOnly runs tests only for Traefik proxy
func TestTraefikOnly(t *testing.T) {
	config := DefaultTestConfig()
	config.ProxyTypes = []string{"traefik"}
	runner := NewTestRunner(config)
	runner.RunAllTests(t)
}

// TestStandaloneOnly runs tests only for standalone mode
func TestStandaloneOnly(t *testing.T) {
	config := DefaultTestConfig()
	config.ProxyTypes = []string{"standalone"}
	runner := NewTestRunner(config)
	runner.RunAllTests(t)
}

// TestSingleModeOnly runs tests only for single compose mode
func TestSingleModeOnly(t *testing.T) {
	config := DefaultTestConfig()
	config.ComposeModes = []string{"single"}
	runner := NewTestRunner(config)
	runner.RunAllTests(t)
}

// TestSeparateModeOnly runs tests only for separate compose mode
func TestSeparateModeOnly(t *testing.T) {
	config := DefaultTestConfig()
	config.ComposeModes = []string{"separate"}
	runner := NewTestRunner(config)
	runner.RunAllTests(t)
}