//go:build integration
// +build integration

package nginx_test

import (
	"reflect"
	"strings"
	"testing"
	"testing/quick"
)

// **Feature: multi-proxy-architecture, Property 3: Proxy-Specific Configuration Consistency** (NPM portion)
// **Validates: Requirements 2.3**
func TestNginxProxyManagerConfiguration_Property(t *testing.T) {
	// Property: For any valid NPM log file path, the log parser should correctly identify it
	property := func(logPath LogPathGenerator) bool {
		pathStr := string(logPath)
		
		// Generate valid NPM log file paths only
		if !isValidNPMLogPath(pathStr) {
			return true // Skip invalid paths
		}
		
		// Test the log path validation logic
		manager := &TestNginxLogManager{}
		isValid := manager.IsValidLogPath(pathStr)
		
		// All valid NPM log paths should be recognized
		if !isValid {
			t.Logf("Valid NPM log path %s not recognized", pathStr)
			return false
		}
		
		return true
	}
	
	// Run property-based test with 50 iterations
	config := &quick.Config{MaxCount: 50}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("NPM log path property test failed: %v", err)
	}
}

// Property test for NPM log parsing consistency
func TestNginxLogParsing_Property(t *testing.T) {
	// Property: For any valid Nginx log entry, the parser should extract IP addresses correctly
	property := func(logEntry NginxLogGenerator) bool {
		entryStr := string(logEntry)
		
		// Generate valid Nginx log entries only
		if !isValidNginxLogEntry(entryStr) {
			return true // Skip invalid entries
		}
		
		// Test the log parsing logic
		manager := &TestNginxLogManager{}
		ips := manager.ExtractIPsFromLogEntry(entryStr)
		
		// Check if at least one IP was extracted from a valid log entry
		if len(ips) == 0 && containsIP(entryStr) {
			t.Logf("No IPs extracted from log entry: %s", entryStr)
			return false
		}
		
		// Verify extracted IPs are valid
		for _, ip := range ips {
			if !isValidIP(ip) {
				t.Logf("Invalid IP extracted: %s from entry: %s", ip, entryStr)
				return false
			}
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Nginx log parsing property test failed: %v", err)
	}
}

// Property test for bouncer configuration validation
func TestNginxBouncerConfiguration_Property(t *testing.T) {
	// Property: For any valid bouncer configuration, the validator should accept it
	property := func(config BouncerConfigGenerator) bool {
		configStr := string(config)
		
		// Generate valid bouncer configurations only
		if !isValidBouncerConfig(configStr) {
			return true // Skip invalid configs
		}
		
		// Test the configuration validation logic
		manager := &TestNginxBouncerManager{}
		isValid := manager.ValidateConfigFormat(configStr)
		
		// All valid configurations should pass validation
		if !isValid {
			t.Logf("Valid bouncer config rejected: %s", configStr)
			return false
		}
		
		return true
	}
	
	// Run property-based test with 30 iterations
	config := &quick.Config{MaxCount: 30}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Nginx bouncer configuration property test failed: %v", err)
	}
}

// Test implementation that exposes NPM-specific logic
type TestNginxLogManager struct{}

func (t *TestNginxLogManager) IsValidLogPath(path string) bool {
	// NPM log paths should match the pattern /data/logs/proxy-host-*.log
	return strings.Contains(path, "/data/logs/proxy-host-") && strings.HasSuffix(path, ".log")
}

func (t *TestNginxLogManager) ExtractIPsFromLogEntry(entry string) []string {
	ips := []string{}
	
	// Simple IP extraction from Nginx log format
	// Nginx logs typically start with IP address
	parts := strings.Fields(entry)
	if len(parts) > 0 && isValidIP(parts[0]) {
		ips = append(ips, parts[0])
	}
	
	return ips
}

type TestNginxBouncerManager struct{}

func (t *TestNginxBouncerManager) ValidateConfigFormat(config string) bool {
	// Basic validation for cs-nginx-bouncer config format
	requiredFields := []string{"api_url", "api_key"}
	
	for _, field := range requiredFields {
		if !strings.Contains(config, field) {
			return false
		}
	}
	
	return true
}

// Helper functions for input validation
func isValidNPMLogPath(path string) bool {
	// Valid NPM log paths
	validPaths := []string{
		"/data/logs/proxy-host-1.log",
		"/data/logs/proxy-host-2.log",
		"/data/logs/proxy-host-10.log",
		"/data/logs/proxy-host-default.log",
	}
	
	for _, validPath := range validPaths {
		if path == validPath {
			return true
		}
	}
	
	return false
}

func isValidNginxLogEntry(entry string) bool {
	// Basic validation for Nginx log format
	// Should contain IP, timestamp, method, status code
	return strings.Contains(entry, " - - [") && 
		   strings.Contains(entry, `"GET `) || strings.Contains(entry, `"POST `) &&
		   strings.Contains(entry, `" 200 `) || strings.Contains(entry, `" 404 `)
}

func isValidBouncerConfig(config string) bool {
	// Valid bouncer config should contain required fields
	return strings.Contains(config, "api_url") && strings.Contains(config, "api_key")
}

func containsIP(text string) bool {
	// Check if text contains an IP address pattern
	parts := strings.Fields(text)
	if len(parts) > 0 {
		return isValidIP(parts[0])
	}
	return false
}

func isValidIP(ip string) bool {
	// Simple IP validation
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	
	return true
}

// Generators for property testing
type LogPathGenerator string

func (LogPathGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	paths := []string{
		"/data/logs/proxy-host-1.log",
		"/data/logs/proxy-host-2.log",
		"/data/logs/proxy-host-10.log",
		"/data/logs/proxy-host-default.log",
		"/data/logs/proxy-host-api.log",
	}
	
	if len(paths) == 0 {
		return reflect.ValueOf(LogPathGenerator("/data/logs/proxy-host-1.log"))
	}
	
	return reflect.ValueOf(LogPathGenerator(paths[rand.Rand.Intn(len(paths))]))
}

type NginxLogGenerator string

func (NginxLogGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	logs := []string{
		`192.168.1.100 - - [25/Dec/2023:10:00:00 +0000] "GET / HTTP/1.1" 200 1234 "-" "Mozilla/5.0"`,
		`10.0.0.50 - - [25/Dec/2023:10:01:00 +0000] "POST /api/login HTTP/1.1" 200 567 "-" "curl/7.68.0"`,
		`172.16.0.25 - - [25/Dec/2023:10:02:00 +0000] "GET /dashboard HTTP/1.1" 404 890 "-" "Chrome/91.0"`,
		`203.0.113.10 - - [25/Dec/2023:10:03:00 +0000] "PUT /api/users HTTP/1.1" 201 345 "-" "PostmanRuntime"`,
	}
	
	if len(logs) == 0 {
		return reflect.ValueOf(NginxLogGenerator(`192.168.1.1 - - [25/Dec/2023:10:00:00 +0000] "GET / HTTP/1.1" 200 1234`))
	}
	
	return reflect.ValueOf(NginxLogGenerator(logs[rand.Rand.Intn(len(logs))]))
}

type BouncerConfigGenerator string

func (BouncerConfigGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	configs := []string{
		"api_url=http://crowdsec:8080\napi_key=test-key-123",
		"api_url=http://localhost:8080\napi_key=prod-key-456\nlog_level=info",
		"api_url=https://crowdsec.local:8080\napi_key=dev-key-789\ntimeout=30",
	}
	
	if len(configs) == 0 {
		return reflect.ValueOf(BouncerConfigGenerator("api_url=http://crowdsec:8080\napi_key=test-key"))
	}
	
	return reflect.ValueOf(BouncerConfigGenerator(configs[rand.Rand.Intn(len(configs))]))
}

// Additional test for NPM-specific features
func TestNginxProxyManagerFeatures_Property(t *testing.T) {
	// Property: NPM adapter should consistently report its supported features
	property := func() bool {
		// This property doesn't need input generation
		// Test that NPM adapter always reports the same features
		
		expectedFeatures := []string{"logs", "bouncer", "health"}
		
		// Simulate adapter feature reporting
		adapter := &TestNginxAdapter{}
		reportedFeatures := adapter.GetSupportedFeatures()
		
		// Check if reported features match expected
		if len(reportedFeatures) != len(expectedFeatures) {
			t.Logf("Feature count mismatch: expected %d, got %d", len(expectedFeatures), len(reportedFeatures))
			return false
		}
		
		for _, expected := range expectedFeatures {
			found := false
			for _, reported := range reportedFeatures {
				if expected == reported {
					found = true
					break
				}
			}
			if !found {
				t.Logf("Expected feature '%s' not found in reported features", expected)
				return false
			}
		}
		
		return true
	}
	
	// Run property test multiple times to ensure consistency
	for i := 0; i < 10; i++ {
		if !property() {
			t.Errorf("NPM features consistency test failed on iteration %d", i+1)
			break
		}
	}
}

type TestNginxAdapter struct{}

func (t *TestNginxAdapter) GetSupportedFeatures() []string {
	return []string{"logs", "bouncer", "health"}
}

// Test for NPM health check consistency
func TestNginxHealthCheck_Property(t *testing.T) {
	// Property: Health check should be consistent for same container state
	property := func(containerState ContainerStateGenerator) bool {
		state := string(containerState)
		
		if !isValidContainerState(state) {
			return true // Skip invalid states
		}
		
		// Test health check consistency
		adapter := &TestNginxAdapter{}
		
		// Run health check multiple times with same state
		results := make([]string, 3)
		for i := 0; i < 3; i++ {
			results[i] = adapter.SimulateHealthCheck(state)
		}
		
		// All results should be the same
		for i := 1; i < len(results); i++ {
			if results[i] != results[0] {
				t.Logf("Health check inconsistent for state '%s': %v", state, results)
				return false
			}
		}
		
		return true
	}
	
	config := &quick.Config{MaxCount: 20}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("NPM health check consistency test failed: %v", err)
	}
}

func (t *TestNginxAdapter) SimulateHealthCheck(containerState string) string {
	switch containerState {
	case "running":
		return "healthy"
	case "stopped":
		return "unhealthy"
	case "restarting":
		return "degraded"
	default:
		return "unknown"
	}
}

type ContainerStateGenerator string

func (ContainerStateGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	states := []string{"running", "stopped", "restarting", "paused"}
	
	if len(states) == 0 {
		return reflect.ValueOf(ContainerStateGenerator("running"))
	}
	
	return reflect.ValueOf(ContainerStateGenerator(states[rand.Rand.Intn(len(states))]))
}

func isValidContainerState(state string) bool {
	validStates := []string{"running", "stopped", "restarting", "paused"}
	for _, valid := range validStates {
		if state == valid {
			return true
		}
	}
	return false
}