package nginx

import (
	"context"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// NginxLogManager implements LogManager for Nginx Proxy Manager
type NginxLogManager struct {
	dockerClient *docker.Client
	cfg          *config.Config
}

// NewNginxLogManager creates a new Nginx log manager
func NewNginxLogManager(dockerClient *docker.Client, cfg *config.Config) *NginxLogManager {
	return &NginxLogManager{
		dockerClient: dockerClient,
		cfg:          cfg,
	}
}

// GetAccessLogs retrieves Nginx Proxy Manager access logs
func (n *NginxLogManager) GetAccessLogs(ctx context.Context, tail int) (string, error) {
	logger.Info("Getting Nginx Proxy Manager access logs", "tail", tail)
	
	containerName := n.cfg.TraefikContainerName // Reused field for NPM container
	
	// NPM stores logs in /data/logs/proxy-host-*.log
	// Try to get the most recent proxy host log
	logs, err := n.dockerClient.ExecCommand(containerName, []string{
		"sh", "-c", fmt.Sprintf("find /data/logs -name 'proxy-host-*.log' -type f -exec tail -n %d {} + 2>/dev/null || echo 'No proxy host logs found'", tail),
	})
	if err != nil {
		// Fallback to container logs if file reading fails
		logger.Warn("Failed to read NPM log files, falling back to container logs", "error", err)
		logs, err = n.dockerClient.GetContainerLogs(containerName, fmt.Sprintf("%d", tail))
		if err != nil {
			return "", fmt.Errorf("failed to get Nginx Proxy Manager logs: %w", err)
		}
	}
	
	return logs, nil
}

// AnalyzeLogs performs advanced analysis of Nginx Proxy Manager logs
func (n *NginxLogManager) AnalyzeLogs(ctx context.Context, tail int) (*models.LogStats, error) {
	logger.Info("Analyzing Nginx Proxy Manager logs", "tail", tail)
	
	logs, err := n.GetAccessLogs(ctx, tail)
	if err != nil {
		return nil, fmt.Errorf("failed to get logs for analysis: %w", err)
	}
	
	// Parse and analyze logs
	stats := n.analyzeLogs(logs)
	return &stats, nil
}

// GetLogPath returns the path to the Nginx Proxy Manager log directory
func (n *NginxLogManager) GetLogPath() string {
	return "/data/logs/proxy-host-*.log"
}

// analyzeLogs performs log analysis and returns statistics
func (n *NginxLogManager) analyzeLogs(logs string) models.LogStats {
	lines := strings.Split(logs, "\n")

	stats := models.LogStats{
		TotalLines:   len(lines),
		TopIPs:       []models.IPCount{},
		StatusCodes:  make(map[string]int),
		HTTPMethods:  make(map[string]int),
		ErrorEntries: []models.LogEntry{},
	}

	ipMap := make(map[string]int)
	
	// Nginx log format patterns
	// Standard Nginx combined log format: IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"
	ipRegex := regexp.MustCompile(`^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})`)
	statusRegex := regexp.MustCompile(`" (\d{3}) `)
	methodRegex := regexp.MustCompile(`"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) `)

	for _, line := range lines {
		if line == "" || strings.Contains(line, "No proxy host logs found") {
			continue
		}

		// Extract IPs (first field in Nginx logs)
		if matches := ipRegex.FindStringSubmatch(line); len(matches) > 1 {
			ip := matches[1]
			ipMap[ip]++
		}

		// Extract status codes
		if matches := statusRegex.FindStringSubmatch(line); len(matches) > 1 {
			stats.StatusCodes[matches[1]]++
		}

		// Extract HTTP methods
		if matches := methodRegex.FindStringSubmatch(line); len(matches) > 1 {
			stats.HTTPMethods[matches[1]]++
		}

		// Collect error entries (4xx and 5xx status codes)
		if statusRegex.MatchString(line) {
			if matches := statusRegex.FindStringSubmatch(line); len(matches) > 1 {
				statusCode := matches[1]
				if strings.HasPrefix(statusCode, "4") || strings.HasPrefix(statusCode, "5") {
					stats.ErrorEntries = append(stats.ErrorEntries, models.LogEntry{
						Timestamp: time.Now(),
						Level:     "error",
						Service:   "nginx-proxy-manager",
						Message:   line,
					})
				}
			}
		}
	}

	// Convert IP map to sorted slice
	for ip, count := range ipMap {
		stats.TopIPs = append(stats.TopIPs, models.IPCount{
			IP:    ip,
			Count: count,
		})
	}
	sort.Slice(stats.TopIPs, func(i, j int) bool {
		return stats.TopIPs[i].Count > stats.TopIPs[j].Count
	})

	// Keep only top 10 IPs
	if len(stats.TopIPs) > 10 {
		stats.TopIPs = stats.TopIPs[:10]
	}

	// Keep only last 20 error entries
	if len(stats.ErrorEntries) > 20 {
		stats.ErrorEntries = stats.ErrorEntries[len(stats.ErrorEntries)-20:]
	}

	return stats
}

// GetErrorLogs retrieves Nginx Proxy Manager error logs
func (n *NginxLogManager) GetErrorLogs(ctx context.Context, tail int) (string, error) {
	logger.Info("Getting Nginx Proxy Manager error logs", "tail", tail)
	
	containerName := n.cfg.TraefikContainerName // Reused field for NPM container
	
	// Try to get error logs from various locations
	logs, err := n.dockerClient.ExecCommand(containerName, []string{
		"sh", "-c", fmt.Sprintf("find /data/logs -name 'error.log' -o -name '*error*.log' -type f -exec tail -n %d {} + 2>/dev/null || echo 'No error logs found'", tail),
	})
	if err != nil {
		// Fallback to container logs if file reading fails
		logger.Warn("Failed to read NPM error log files, falling back to container logs", "error", err)
		logs, err = n.dockerClient.GetContainerLogs(containerName, fmt.Sprintf("%d", tail))
		if err != nil {
			return "", fmt.Errorf("failed to get Nginx Proxy Manager error logs: %w", err)
		}
	}
	
	return logs, nil
}

// GetProxyHostLogs retrieves logs for a specific proxy host
func (n *NginxLogManager) GetProxyHostLogs(ctx context.Context, hostID string, tail int) (string, error) {
	logger.Info("Getting proxy host logs", "host_id", hostID, "tail", tail)
	
	containerName := n.cfg.TraefikContainerName // Reused field for NPM container
	
	// Get logs for specific proxy host
	logFile := fmt.Sprintf("/data/logs/proxy-host-%s.log", hostID)
	logs, err := n.dockerClient.ExecCommand(containerName, []string{
		"tail", "-n", fmt.Sprintf("%d", tail), logFile,
	})
	if err != nil {
		return "", fmt.Errorf("failed to get proxy host logs for %s: %w", hostID, err)
	}
	
	return logs, nil
}

// ListProxyHostLogFiles lists all available proxy host log files
func (n *NginxLogManager) ListProxyHostLogFiles(ctx context.Context) ([]string, error) {
	logger.Info("Listing proxy host log files")
	
	containerName := n.cfg.TraefikContainerName // Reused field for NPM container
	
	// List all proxy host log files
	output, err := n.dockerClient.ExecCommand(containerName, []string{
		"sh", "-c", "find /data/logs -name 'proxy-host-*.log' -type f | sort",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list proxy host log files: %w", err)
	}
	
	if output == "" {
		return []string{}, nil
	}
	
	files := strings.Split(strings.TrimSpace(output), "\n")
	return files, nil
}