package traefik

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

// TraefikLogManager implements LogManager for Traefik
type TraefikLogManager struct {
	dockerClient *docker.Client
	cfg          *config.Config
}

// NewTraefikLogManager creates a new Traefik log manager
func NewTraefikLogManager(dockerClient *docker.Client, cfg *config.Config) *TraefikLogManager {
	return &TraefikLogManager{
		dockerClient: dockerClient,
		cfg:          cfg,
	}
}

// GetAccessLogs retrieves Traefik access logs
func (t *TraefikLogManager) GetAccessLogs(ctx context.Context, tail int) (string, error) {
	logger.Info("Getting Traefik access logs", "tail", tail)
	
	// Try to read from access log file first
	accessLogPath := "/var/log/traefik/access.log"
	if t.cfg.TraefikAccessLog != "" {
		accessLogPath = t.cfg.TraefikAccessLog
	}
	
	logs, err := t.dockerClient.ExecCommand(t.cfg.TraefikContainerName, []string{
		"tail", "-n", fmt.Sprintf("%d", tail), accessLogPath,
	})
	if err != nil {
		// Fallback to container logs if file reading fails
		logger.Warn("Failed to read access log file, falling back to container logs", "error", err)
		logs, err = t.dockerClient.GetContainerLogs(t.cfg.TraefikContainerName, fmt.Sprintf("%d", tail))
		if err != nil {
			return "", fmt.Errorf("failed to get Traefik logs: %w", err)
		}
	}
	
	return logs, nil
}

// AnalyzeLogs performs advanced analysis of Traefik logs
func (t *TraefikLogManager) AnalyzeLogs(ctx context.Context, tail int) (*models.LogStats, error) {
	logger.Info("Analyzing Traefik logs", "tail", tail)
	
	logs, err := t.GetAccessLogs(ctx, tail)
	if err != nil {
		return nil, fmt.Errorf("failed to get logs for analysis: %w", err)
	}
	
	// Parse and analyze logs
	stats := t.analyzeLogs(logs)
	return &stats, nil
}

// GetLogPath returns the path to the Traefik access log file
func (t *TraefikLogManager) GetLogPath() string {
	if t.cfg.TraefikAccessLog != "" {
		return t.cfg.TraefikAccessLog
	}
	return "/var/log/traefik/access.log"
}

// analyzeLogs performs log analysis and returns statistics
func (t *TraefikLogManager) analyzeLogs(logs string) models.LogStats {
	lines := strings.Split(logs, "\n")

	stats := models.LogStats{
		TotalLines:   len(lines),
		TopIPs:       []models.IPCount{},
		StatusCodes:  make(map[string]int),
		HTTPMethods:  make(map[string]int),
		ErrorEntries: []models.LogEntry{},
	}

	ipMap := make(map[string]int)
	ipRegex := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	statusRegex := regexp.MustCompile(`\s(2\d{2}|3\d{2}|4\d{2}|5\d{2})\s`)
	methodRegex := regexp.MustCompile(`"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)`)

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Extract IPs
		if ips := ipRegex.FindAllString(line, -1); len(ips) > 0 {
			for _, ip := range ips {
				ipMap[ip]++
			}
		}

		// Extract status codes
		if matches := statusRegex.FindStringSubmatch(line); len(matches) > 1 {
			stats.StatusCodes[matches[1]]++
		}

		// Extract HTTP methods
		if matches := methodRegex.FindStringSubmatch(line); len(matches) > 1 {
			stats.HTTPMethods[matches[1]]++
		}

		// Collect error entries
		if strings.Contains(strings.ToLower(line), "error") ||
			strings.Contains(line, "5") && statusRegex.MatchString(line) {
			stats.ErrorEntries = append(stats.ErrorEntries, models.LogEntry{
				Timestamp: time.Now(),
				Level:     "error",
				Service:   "traefik",
				Message:   line,
			})
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

// GetErrorLogs retrieves Traefik error logs
func (t *TraefikLogManager) GetErrorLogs(ctx context.Context, tail int) (string, error) {
	logger.Info("Getting Traefik error logs", "tail", tail)
	
	// Try to read from error log file
	errorLogPath := "/var/log/traefik/error.log"
	if t.cfg.TraefikErrorLog != "" {
		errorLogPath = t.cfg.TraefikErrorLog
	}
	
	logs, err := t.dockerClient.ExecCommand(t.cfg.TraefikContainerName, []string{
		"tail", "-n", fmt.Sprintf("%d", tail), errorLogPath,
	})
	if err != nil {
		// Fallback to container logs if file reading fails
		logger.Warn("Failed to read error log file, falling back to container logs", "error", err)
		logs, err = t.dockerClient.GetContainerLogs(t.cfg.TraefikContainerName, fmt.Sprintf("%d", tail))
		if err != nil {
			return "", fmt.Errorf("failed to get Traefik error logs: %w", err)
		}
	}
	
	return logs, nil
}