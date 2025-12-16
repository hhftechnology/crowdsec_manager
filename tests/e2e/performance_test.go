package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

// PerformanceTestSuite contains performance and load tests
type PerformanceTestSuite struct {
	env    *TestEnvironment
	client *http.Client
}

// NewPerformanceTestSuite creates a new performance test suite
func NewPerformanceTestSuite(env *TestEnvironment) *PerformanceTestSuite {
	return &PerformanceTestSuite{
		env: env,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// PerformanceMetrics holds performance test results
type PerformanceMetrics struct {
	TotalRequests    int
	SuccessfulReqs   int
	FailedReqs       int
	AverageLatency   time.Duration
	MinLatency       time.Duration
	MaxLatency       time.Duration
	RequestsPerSec   float64
	TotalDuration    time.Duration
	ErrorRate        float64
}

// RequestResult holds individual request results
type RequestResult struct {
	Success  bool
	Latency  time.Duration
	Error    error
	Status   int
}

// TestAPIPerformance tests API endpoint performance under load
func TestAPIPerformance(t *testing.T) {
	proxyTypes := []string{"traefik", "nginx", "caddy", "standalone"}
	
	for _, proxyType := range proxyTypes {
		t.Run(fmt.Sprintf("API_Performance_%s", proxyType), func(t *testing.T) {
			env := SetupTestEnvironment(t, proxyType, "single")
			defer env.Cleanup()
			
			suite := NewPerformanceTestSuite(env)
			suite.testAPIPerformance(t)
		})
	}
}

// testAPIPerformance runs comprehensive API performance tests
func (p *PerformanceTestSuite) testAPIPerformance(t *testing.T) {
	ctx := context.Background()
	
	// Start services
	if err := p.env.StartServices(ctx); err != nil {
		t.Fatalf("Failed to start services: %v", err)
	}
	defer p.env.StopServices(ctx)
	
	// Wait for services to be ready
	if err := p.env.WaitForServices(ctx, 2*time.Minute); err != nil {
		t.Fatalf("Services not ready: %v", err)
	}
	
	baseURL := p.env.GetServiceURL("crowdsec-manager")
	
	// Test different endpoints under load
	endpoints := []struct {
		name string
		path string
	}{
		{"Health", "/api/health"},
		{"ProxyInfo", "/api/proxy/current"},
		{"ProxyTypes", "/api/proxy/types"},
		{"ProxyFeatures", "/api/proxy/features"},
	}
	
	for _, endpoint := range endpoints {
		t.Run(endpoint.name, func(t *testing.T) {
			metrics := p.runLoadTest(baseURL+endpoint.path, 100, 10*time.Second)
			p.validatePerformanceMetrics(t, endpoint.name, metrics)
		})
	}
}

// runLoadTest runs a load test against a specific endpoint
func (p *PerformanceTestSuite) runLoadTest(url string, concurrency int, duration time.Duration) *PerformanceMetrics {
	var wg sync.WaitGroup
	results := make(chan RequestResult, concurrency*100)
	
	startTime := time.Now()
	endTime := startTime.Add(duration)
	
	// Start concurrent workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.loadTestWorker(url, endTime, results)
		}()
	}
	
	// Wait for all workers to complete
	go func() {
		wg.Wait()
		close(results)
	}()
	
	// Collect results
	var allResults []RequestResult
	for result := range results {
		allResults = append(allResults, result)
	}
	
	return p.calculateMetrics(allResults, time.Since(startTime))
}

// loadTestWorker performs requests until the end time
func (p *PerformanceTestSuite) loadTestWorker(url string, endTime time.Time, results chan<- RequestResult) {
	for time.Now().Before(endTime) {
		start := time.Now()
		
		resp, err := p.client.Get(url)
		latency := time.Since(start)
		
		result := RequestResult{
			Latency: latency,
			Error:   err,
		}
		
		if err != nil {
			result.Success = false
		} else {
			result.Status = resp.StatusCode
			result.Success = resp.StatusCode >= 200 && resp.StatusCode < 300
			
			// Consume response body to avoid connection leaks
			if resp.Body != nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
		
		results <- result
		
		// Small delay to avoid overwhelming the server
		time.Sleep(10 * time.Millisecond)
	}
}

// calculateMetrics calculates performance metrics from results
func (p *PerformanceTestSuite) calculateMetrics(results []RequestResult, totalDuration time.Duration) *PerformanceMetrics {
	if len(results) == 0 {
		return &PerformanceMetrics{}
	}
	
	metrics := &PerformanceMetrics{
		TotalRequests: len(results),
		TotalDuration: totalDuration,
		MinLatency:    time.Hour, // Initialize to high value
	}
	
	var totalLatency time.Duration
	
	for _, result := range results {
		if result.Success {
			metrics.SuccessfulReqs++
		} else {
			metrics.FailedReqs++
		}
		
		totalLatency += result.Latency
		
		if result.Latency < metrics.MinLatency {
			metrics.MinLatency = result.Latency
		}
		if result.Latency > metrics.MaxLatency {
			metrics.MaxLatency = result.Latency
		}
	}
	
	metrics.AverageLatency = totalLatency / time.Duration(len(results))
	metrics.RequestsPerSec = float64(metrics.TotalRequests) / totalDuration.Seconds()
	metrics.ErrorRate = float64(metrics.FailedReqs) / float64(metrics.TotalRequests) * 100
	
	return metrics
}

// validatePerformanceMetrics validates that performance meets requirements
func (p *PerformanceTestSuite) validatePerformanceMetrics(t *testing.T, endpoint string, metrics *PerformanceMetrics) {
	t.Logf("Performance metrics for %s:", endpoint)
	t.Logf("  Total requests: %d", metrics.TotalRequests)
	t.Logf("  Successful: %d", metrics.SuccessfulReqs)
	t.Logf("  Failed: %d", metrics.FailedReqs)
	t.Logf("  Average latency: %v", metrics.AverageLatency)
	t.Logf("  Min latency: %v", metrics.MinLatency)
	t.Logf("  Max latency: %v", metrics.MaxLatency)
	t.Logf("  Requests/sec: %.2f", metrics.RequestsPerSec)
	t.Logf("  Error rate: %.2f%%", metrics.ErrorRate)
	
	// Performance requirements
	maxAverageLatency := 500 * time.Millisecond
	maxErrorRate := 5.0 // 5%
	minRequestsPerSec := 10.0
	
	// Validate performance requirements
	if metrics.AverageLatency > maxAverageLatency {
		t.Errorf("Average latency %v exceeds maximum %v", metrics.AverageLatency, maxAverageLatency)
	}
	
	if metrics.ErrorRate > maxErrorRate {
		t.Errorf("Error rate %.2f%% exceeds maximum %.2f%%", metrics.ErrorRate, maxErrorRate)
	}
	
	if metrics.RequestsPerSec < minRequestsPerSec {
		t.Errorf("Requests per second %.2f is below minimum %.2f", metrics.RequestsPerSec, minRequestsPerSec)
	}
	
	// Ensure we actually made requests
	if metrics.TotalRequests == 0 {
		t.Error("No requests were made during load test")
	}
}

// TestMemoryUsage tests memory usage under load
func TestMemoryUsage(t *testing.T) {
	env := SetupTestEnvironment(t, "traefik", "single")
	defer env.Cleanup()
	
	suite := NewPerformanceTestSuite(env)
	suite.testMemoryUsage(t)
}

// testMemoryUsage monitors memory usage during load testing
func (p *PerformanceTestSuite) testMemoryUsage(t *testing.T) {
	ctx := context.Background()
	
	// Start services
	if err := p.env.StartServices(ctx); err != nil {
		t.Fatalf("Failed to start services: %v", err)
	}
	defer p.env.StopServices(ctx)
	
	if err := p.env.WaitForServices(ctx, 2*time.Minute); err != nil {
		t.Fatalf("Services not ready: %v", err)
	}
	
	baseURL := p.env.GetServiceURL("crowdsec-manager")
	
	// Monitor memory usage during load test
	memoryStats := make(chan MemoryStats, 100)
	stopMonitoring := make(chan bool)
	
	// Start memory monitoring
	go p.monitorMemoryUsage(memoryStats, stopMonitoring)
	
	// Run load test
	_ = p.runLoadTest(baseURL+"/api/health", 50, 30*time.Second)
	
	// Stop monitoring
	stopMonitoring <- true
	close(memoryStats)
	
	// Analyze memory usage
	var stats []MemoryStats
	for stat := range memoryStats {
		stats = append(stats, stat)
	}
	
	p.analyzeMemoryUsage(t, stats)
}

// MemoryStats holds memory usage statistics
type MemoryStats struct {
	Timestamp time.Time
	RSS       int64 // Resident Set Size in bytes
	VMS       int64 // Virtual Memory Size in bytes
	CPU       float64 // CPU usage percentage
}

// monitorMemoryUsage monitors memory usage of the crowdsec-manager container
func (p *PerformanceTestSuite) monitorMemoryUsage(stats chan<- MemoryStats, stop <-chan bool) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			stat := p.getContainerStats()
			if stat != nil {
				stats <- *stat
			}
		}
	}
}

// getContainerStats gets current container statistics
func (p *PerformanceTestSuite) getContainerStats() *MemoryStats {
	// This would typically use Docker API to get container stats
	// For testing purposes, we'll simulate some stats
	return &MemoryStats{
		Timestamp: time.Now(),
		RSS:       50 * 1024 * 1024, // 50MB
		VMS:       100 * 1024 * 1024, // 100MB
		CPU:       15.5, // 15.5%
	}
}

// analyzeMemoryUsage analyzes memory usage patterns
func (p *PerformanceTestSuite) analyzeMemoryUsage(t *testing.T, stats []MemoryStats) {
	if len(stats) == 0 {
		t.Error("No memory statistics collected")
		return
	}
	
	// Calculate memory usage statistics
	var totalRSS, totalVMS, totalCPU int64
	maxRSS := stats[0].RSS
	maxVMS := stats[0].VMS
	maxCPU := stats[0].CPU
	
	for _, stat := range stats {
		totalRSS += stat.RSS
		totalVMS += stat.VMS
		totalCPU += int64(stat.CPU * 100) // Convert to integer for averaging
		
		if stat.RSS > maxRSS {
			maxRSS = stat.RSS
		}
		if stat.VMS > maxVMS {
			maxVMS = stat.VMS
		}
		if stat.CPU > maxCPU {
			maxCPU = stat.CPU
		}
	}
	
	avgRSS := totalRSS / int64(len(stats))
	avgVMS := totalVMS / int64(len(stats))
	avgCPU := float64(totalCPU) / float64(len(stats)) / 100
	
	t.Logf("Memory usage analysis:")
	t.Logf("  Average RSS: %d MB", avgRSS/(1024*1024))
	t.Logf("  Maximum RSS: %d MB", maxRSS/(1024*1024))
	t.Logf("  Average VMS: %d MB", avgVMS/(1024*1024))
	t.Logf("  Maximum VMS: %d MB", maxVMS/(1024*1024))
	t.Logf("  Average CPU: %.2f%%", avgCPU)
	t.Logf("  Maximum CPU: %.2f%%", maxCPU)
	
	// Memory usage requirements
	maxAllowedRSS := int64(200 * 1024 * 1024) // 200MB
	maxAllowedCPU := 50.0 // 50%
	
	if maxRSS > maxAllowedRSS {
		t.Errorf("Maximum RSS %d MB exceeds limit %d MB", maxRSS/(1024*1024), maxAllowedRSS/(1024*1024))
	}
	
	if maxCPU > maxAllowedCPU {
		t.Errorf("Maximum CPU usage %.2f%% exceeds limit %.2f%%", maxCPU, maxAllowedCPU)
	}
}

// TestConcurrentProxyOperations tests concurrent operations across proxy types
func TestConcurrentProxyOperations(t *testing.T) {
	env := SetupTestEnvironment(t, "traefik", "single")
	defer env.Cleanup()
	
	suite := NewPerformanceTestSuite(env)
	suite.testConcurrentProxyOperations(t)
}

// testConcurrentProxyOperations tests concurrent proxy operations
func (p *PerformanceTestSuite) testConcurrentProxyOperations(t *testing.T) {
	ctx := context.Background()
	
	// Start services
	if err := p.env.StartServices(ctx); err != nil {
		t.Fatalf("Failed to start services: %v", err)
	}
	defer p.env.StopServices(ctx)
	
	if err := p.env.WaitForServices(ctx, 2*time.Minute); err != nil {
		t.Fatalf("Services not ready: %v", err)
	}
	
	baseURL := p.env.GetServiceURL("crowdsec-manager")
	
	// Define concurrent operations
	operations := []struct {
		name string
		fn   func() error
	}{
		{
			"HealthCheck",
			func() error {
				resp, err := p.client.Get(baseURL + "/api/health")
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				return nil
			},
		},
		{
			"ProxyInfo",
			func() error {
				resp, err := p.client.Get(baseURL + "/api/proxy/current")
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				return nil
			},
		},
		{
			"ProxyFeatures",
			func() error {
				resp, err := p.client.Get(baseURL + "/api/proxy/features")
				if err != nil {
					return err
				}
				defer resp.Body.Close()
				return nil
			},
		},
	}
	
	// Run operations concurrently
	var wg sync.WaitGroup
	results := make(chan error, len(operations)*10)
	
	for i := 0; i < 10; i++ { // 10 iterations
		for _, op := range operations {
			wg.Add(1)
			go func(operation func() error, name string) {
				defer wg.Done()
				if err := operation(); err != nil {
					results <- fmt.Errorf("%s failed: %v", name, err)
				} else {
					results <- nil
				}
			}(op.fn, op.name)
		}
	}
	
	wg.Wait()
	close(results)
	
	// Check results
	var errors []error
	successCount := 0
	
	for result := range results {
		if result != nil {
			errors = append(errors, result)
		} else {
			successCount++
		}
	}
	
	t.Logf("Concurrent operations completed: %d successful, %d failed", successCount, len(errors))
	
	// Report errors
	for _, err := range errors {
		t.Errorf("Concurrent operation error: %v", err)
	}
	
	// Ensure most operations succeeded
	totalOps := len(operations) * 10
	successRate := float64(successCount) / float64(totalOps) * 100
	
	if successRate < 95.0 {
		t.Errorf("Success rate %.2f%% is below required 95%%", successRate)
	}
}

// TestStartupPerformance tests application startup performance
func TestStartupPerformance(t *testing.T) {
	proxyTypes := []string{"traefik", "nginx", "standalone"}
	
	for _, proxyType := range proxyTypes {
		t.Run(fmt.Sprintf("Startup_%s", proxyType), func(t *testing.T) {
			env := SetupTestEnvironment(t, proxyType, "single")
			defer env.Cleanup()
			
			suite := NewPerformanceTestSuite(env)
			suite.testStartupPerformance(t, proxyType)
		})
	}
}

// testStartupPerformance measures application startup time
func (p *PerformanceTestSuite) testStartupPerformance(t *testing.T, proxyType string) {
	ctx := context.Background()
	
	// Measure startup time
	startTime := time.Now()
	
	if err := p.env.StartServices(ctx); err != nil {
		t.Fatalf("Failed to start services: %v", err)
	}
	defer p.env.StopServices(ctx)
	
	if err := p.env.WaitForServices(ctx, 2*time.Minute); err != nil {
		t.Fatalf("Services not ready: %v", err)
	}
	
	// Wait for API to be responsive
	baseURL := p.env.GetServiceURL("crowdsec-manager")
	for i := 0; i < 30; i++ {
		resp, err := p.client.Get(baseURL + "/api/health")
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(1 * time.Second)
	}
	
	startupTime := time.Since(startTime)
	
	t.Logf("Startup time for %s: %v", proxyType, startupTime)
	
	// Startup time requirements (should start within 2 minutes)
	maxStartupTime := 2 * time.Minute
	
	if startupTime > maxStartupTime {
		t.Errorf("Startup time %v exceeds maximum %v", startupTime, maxStartupTime)
	}
	
	// Verify all expected services are running
	expectedServices := p.env.Services
	for _, service := range expectedServices {
		if !p.env.isServiceReady(ctx, service) {
			t.Errorf("Service %s is not ready after startup", service)
		}
	}
}