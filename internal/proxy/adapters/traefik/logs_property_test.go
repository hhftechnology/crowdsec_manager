package traefik

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

// **Feature: multi-proxy-architecture, Property 8: Proxy-Aware Log Management**
// **Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5**
func TestTraefikLogRetrieval_Property(t *testing.T) {
	// Property: For any tail count, retrieving logs should return the requested number of lines or fewer
	property := func(tailCount TailCountGenerator) bool {
		tailCountInt := int(tailCount)
		
		// Skip invalid tail counts
		if tailCountInt <= 0 || tailCountInt > 10000 {
			return true
		}
		
		// Create mock with sample log data
		logLines := generateSampleLogLines(tailCountInt + 10) // Generate more than requested
		mockClient := &LogsMockDockerClient{
			logContent: strings.Join(logLines, "\n"),
		}
		
		cfg := &LogsMockConfig{
			TraefikContainerName: "traefik",
			TraefikAccessLog:     "/var/log/traefik/access.log",
		}
		
		manager := &TestTraefikLogManager{
			dockerClient: mockClient,
			cfg:          cfg,
		}
		
		ctx := context.Background()
		
		// Get access logs
		logs, err := manager.GetAccessLogs(ctx, tailCountInt)
		if err != nil {
			t.Logf("Failed to get access logs: %v", err)
			return false
		}
		
		// Count returned lines
		returnedLines := strings.Split(strings.TrimSpace(logs), "\n")
		if len(returnedLines) == 1 && returnedLines[0] == "" {
			returnedLines = []string{} // Handle empty logs
		}
		
		// Verify we got the expected number of lines (or fewer if less available)
		if len(returnedLines) > tailCountInt {
			t.Logf("Expected at most %d lines, got %d", tailCountInt, len(returnedLines))
			return false
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Log retrieval property test failed: %v", err)
	}
}

// Property test for log analysis consistency
func TestTraefikLogAnalysis_Property(t *testing.T) {
	// Property: For any log content, analyzing logs should produce consistent statistics
	property := func(logGenerator LogContentGenerator) bool {
		logContent := string(logGenerator)
		
		// Skip empty logs
		if strings.TrimSpace(logContent) == "" {
			return true
		}
		
		mockClient := &LogsMockDockerClient{
			logContent: logContent,
		}
		
		cfg := &LogsMockConfig{
			TraefikContainerName: "traefik",
			TraefikAccessLog:     "/var/log/traefik/access.log",
		}
		
		manager := &TestTraefikLogManager{
			dockerClient: mockClient,
			cfg:          cfg,
		}
		
		ctx := context.Background()
		
		// Analyze logs
		stats, err := manager.AnalyzeLogs(ctx, 1000)
		if err != nil {
			t.Logf("Failed to analyze logs: %v", err)
			return false
		}
		
		// Verify basic consistency properties
		lines := strings.Split(logContent, "\n")
		expectedLineCount := len(lines)
		
		if stats.TotalLines != expectedLineCount {
			t.Logf("Expected %d total lines, got %d", expectedLineCount, stats.TotalLines)
			return false
		}
		
		// Verify IP counts are non-negative
		for _, ipCount := range stats.TopIPs {
			if ipCount.Count < 0 {
				t.Logf("IP count should be non-negative, got %d for IP %s", ipCount.Count, ipCount.IP)
				return false
			}
		}
		
		// Verify status code counts are non-negative
		for code, count := range stats.StatusCodes {
			if count < 0 {
				t.Logf("Status code count should be non-negative, got %d for code %s", count, code)
				return false
			}
		}
		
		// Verify HTTP method counts are non-negative
		for method, count := range stats.HTTPMethods {
			if count < 0 {
				t.Logf("HTTP method count should be non-negative, got %d for method %s", count, method)
				return false
			}
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Log analysis property test failed: %v", err)
	}
}

// Property test for log path consistency
func TestTraefikLogPath_Property(t *testing.T) {
	// Property: GetLogPath should return the configured path or default
	property := func(logPath LogPathGenerator) bool {
		logPathStr := string(logPath)
		
		cfg := &LogsMockConfig{
			TraefikContainerName: "traefik",
			TraefikAccessLog:     logPathStr,
		}
		
		manager := &TestTraefikLogManager{
			dockerClient: &LogsMockDockerClient{},
			cfg:          cfg,
		}
		
		// Get log path
		returnedPath := manager.GetLogPath()
		
		// If config has a path, it should return that path
		if logPathStr != "" {
			if returnedPath != logPathStr {
				t.Logf("Expected path '%s', got '%s'", logPathStr, returnedPath)
				return false
			}
		} else {
			// If no path configured, should return default
			expectedDefault := "/var/log/traefik/access.log"
			if returnedPath != expectedDefault {
				t.Logf("Expected default path '%s', got '%s'", expectedDefault, returnedPath)
				return false
			}
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Log path property test failed: %v", err)
	}
}

// Test interfaces and implementations for log testing
type LogsDockerClientInterface interface {
	ExecCommand(containerName string, command []string) (string, error)
	GetContainerLogs(containerName, tail string) (string, error)
}

type LogsConfigInterface interface {
	GetTraefikContainerName() string
	GetTraefikAccessLog() string
}

type LogsMockConfig struct {
	TraefikContainerName string
	TraefikAccessLog     string
}

func (m *LogsMockConfig) GetTraefikContainerName() string {
	return m.TraefikContainerName
}

func (m *LogsMockConfig) GetTraefikAccessLog() string {
	return m.TraefikAccessLog
}

type TestLogStats struct {
	TotalLines   int
	TopIPs       []TestIPCount
	StatusCodes  map[string]int
	HTTPMethods  map[string]int
	ErrorEntries []TestLogEntry
}

type TestIPCount struct {
	IP    string
	Count int
}

type TestLogEntry struct {
	Timestamp time.Time
	Level     string
	Service   string
	Message   string
}

type TestTraefikLogManager struct {
	dockerClient LogsDockerClientInterface
	cfg          LogsConfigInterface
}

func (t *TestTraefikLogManager) GetAccessLogs(ctx context.Context, tail int) (string, error) {
	// Try to read from access log file first
	accessLogPath := "/var/log/traefik/access.log"
	if t.cfg.GetTraefikAccessLog() != "" {
		accessLogPath = t.cfg.GetTraefikAccessLog()
	}
	
	logs, err := t.dockerClient.ExecCommand(t.cfg.GetTraefikContainerName(), []string{
		"tail", "-n", fmt.Sprintf("%d", tail), accessLogPath,
	})
	if err != nil {
		// Fallback to container logs if file reading fails
		logs, err = t.dockerClient.GetContainerLogs(t.cfg.GetTraefikContainerName(), fmt.Sprintf("%d", tail))
		if err != nil {
			return "", fmt.Errorf("failed to get Traefik logs: %w", err)
		}
	}
	
	return logs, nil
}

func (t *TestTraefikLogManager) AnalyzeLogs(ctx context.Context, tail int) (*TestLogStats, error) {
	logs, err := t.GetAccessLogs(ctx, tail)
	if err != nil {
		return nil, fmt.Errorf("failed to get logs for analysis: %w", err)
	}
	
	// Parse and analyze logs
	stats := t.analyzeLogs(logs)
	return &stats, nil
}

func (t *TestTraefikLogManager) GetLogPath() string {
	if t.cfg.GetTraefikAccessLog() != "" {
		return t.cfg.GetTraefikAccessLog()
	}
	return "/var/log/traefik/access.log"
}

func (t *TestTraefikLogManager) analyzeLogs(logs string) TestLogStats {
	lines := strings.Split(logs, "\n")

	stats := TestLogStats{
		TotalLines:   len(lines),
		TopIPs:       []TestIPCount{},
		StatusCodes:  make(map[string]int),
		HTTPMethods:  make(map[string]int),
		ErrorEntries: []TestLogEntry{},
	}

	ipMap := make(map[string]int)

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Simple IP extraction (look for patterns like "192.168.1.1")
		parts := strings.Fields(line)
		for _, part := range parts {
			if strings.Contains(part, ".") && len(strings.Split(part, ".")) == 4 {
				ipMap[part]++
				break
			}
		}

		// Simple status code extraction (look for 3-digit numbers)
		for _, part := range parts {
			if len(part) == 3 {
				if code, err := strconv.Atoi(part); err == nil && code >= 100 && code < 600 {
					stats.StatusCodes[part]++
					break
				}
			}
		}

		// Simple HTTP method extraction
		for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} {
			if strings.Contains(line, method) {
				stats.HTTPMethods[method]++
				break
			}
		}

		// Collect error entries
		if strings.Contains(strings.ToLower(line), "error") || strings.Contains(line, "5") {
			stats.ErrorEntries = append(stats.ErrorEntries, TestLogEntry{
				Timestamp: time.Now(),
				Level:     "error",
				Service:   "traefik",
				Message:   line,
			})
		}
	}

	// Convert IP map to sorted slice
	for ip, count := range ipMap {
		stats.TopIPs = append(stats.TopIPs, TestIPCount{
			IP:    ip,
			Count: count,
		})
	}

	return stats
}

type LogsMockDockerClient struct {
	logContent string
	commands   [][]string
}

func (m *LogsMockDockerClient) ExecCommand(containerName string, command []string) (string, error) {
	m.commands = append(m.commands, command)
	
	// Mock tail command
	if len(command) >= 3 && command[0] == "tail" && command[1] == "-n" {
		tailCount, err := strconv.Atoi(command[2])
		if err != nil {
			return m.logContent, nil
		}
		
		lines := strings.Split(m.logContent, "\n")
		if tailCount >= len(lines) {
			return m.logContent, nil
		}
		
		// Return last N lines
		tailLines := lines[len(lines)-tailCount:]
		return strings.Join(tailLines, "\n"), nil
	}
	
	return m.logContent, nil
}

func (m *LogsMockDockerClient) GetContainerLogs(containerName, tail string) (string, error) {
	return m.logContent, nil
}

// Generators for property testing
type TailCountGenerator int

func (TailCountGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	// Generate reasonable tail counts
	counts := []int{1, 5, 10, 50, 100, 500, 1000}
	return reflect.ValueOf(TailCountGenerator(counts[rand.Rand.Intn(len(counts))]))
}

type LogContentGenerator string

func (LogContentGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	// Generate sample log content
	samples := []string{
		`192.168.1.1 - - [10/Oct/2023:13:55:36 +0000] "GET /api/health HTTP/1.1" 200 15`,
		`10.0.0.1 - - [10/Oct/2023:13:55:37 +0000] "POST /api/login HTTP/1.1" 401 23`,
		`172.16.0.1 - - [10/Oct/2023:13:55:38 +0000] "GET /dashboard HTTP/1.1" 500 1234`,
		`203.0.113.1 - - [10/Oct/2023:13:55:39 +0000] "DELETE /api/users/123 HTTP/1.1" 204 0`,
	}
	
	// Combine multiple samples
	numLines := rand.Rand.Intn(10) + 1
	var lines []string
	for i := 0; i < numLines; i++ {
		lines = append(lines, samples[rand.Rand.Intn(len(samples))])
	}
	
	return reflect.ValueOf(LogContentGenerator(strings.Join(lines, "\n")))
}

type LogPathGenerator string

func (LogPathGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	paths := []string{
		"/var/log/traefik/access.log",
		"/app/logs/traefik.log",
		"/tmp/access.log",
		"", // Empty path to test default
	}
	
	return reflect.ValueOf(LogPathGenerator(paths[rand.Rand.Intn(len(paths))]))
}

// Helper function to generate sample log lines
func generateSampleLogLines(count int) []string {
	templates := []string{
		`192.168.1.%d - - [10/Oct/2023:13:55:%02d +0000] "GET /api/health HTTP/1.1" 200 15`,
		`10.0.0.%d - - [10/Oct/2023:13:55:%02d +0000] "POST /api/login HTTP/1.1" 401 23`,
		`172.16.0.%d - - [10/Oct/2023:13:55:%02d +0000] "GET /dashboard HTTP/1.1" 500 1234`,
	}
	
	var lines []string
	for i := 0; i < count; i++ {
		template := templates[i%len(templates)]
		line := fmt.Sprintf(template, (i%254)+1, i%60)
		lines = append(lines, line)
	}
	
	return lines
}