package handlers

import (
	"encoding/json"
	"strings"
	"time"

	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// truncateString truncates a string to a maximum length for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "... (truncated)"
}

// Helper functions for safe type conversion from map[string]interface{}
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case float64:
			return int(val)
		case int:
			return val
		case int64:
			return int(val)
		}
	}
	return 0
}

// calculateUntil calculates the expiration time from created_at and duration
// Duration format: "3h57m35s", "1h", "30m", etc.
func calculateUntil(createdAtStr, durationStr string) *time.Time {
	if createdAtStr == "" || durationStr == "" {
		return nil
	}

	// Parse created_at timestamp - try multiple formats
	var createdAt time.Time
	
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05 +0000 UTC",
		time.RFC3339Nano,
	}
	
	for _, format := range formats {
		if t, err := time.Parse(format, createdAtStr); err == nil {
			createdAt = t
			break
		}
	}
	
	if createdAt.IsZero() {
		return nil
	}

	// Parse duration (e.g., "3h57m35s", "1h", "30m")
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return nil
	}

	// Calculate until time
	until := createdAt.Add(duration)
	return &until
}

func activeFilters(c *gin.Context) map[string]string {
	filters := make(map[string]string)
	for _, key := range []string{"since", "until", "type", "scope", "origin", "value", "scenario", "ip", "range"} {
		if val := c.Query(key); val != "" && val != "all" {
			filters[key] = val
		}
	}
	return filters
}

// GetConsoleStatusHelper executes the console status command and parses the result
func GetConsoleStatusHelper(dockerClient interface {
	ExecCommand(containerName string, cmd []string) (string, error)
}, containerName string) (models.ConsoleStatus, error) {
	output, err := dockerClient.ExecCommand(containerName, []string{
		"cscli", "console", "status", "-o", "json",
	})
	if err != nil {
		return models.ConsoleStatus{}, err
	}

	// Log the raw output for debugging
	logger.Info("Console status raw output", "output", output)

	var status models.ConsoleStatus
	if err := json.Unmarshal([]byte(output), &status); err != nil {
		logger.Warn("Failed to parse console status JSON, attempting fallback", "error", err)
		
		// Fallback to simple string check if JSON parsing fails
		// This handles cases where older versions might not output valid JSON or other issues
		// We check for various formats (YAML-like, JSON with/without spaces)
		status.Enrolled = strings.Contains(output, "enrolled: true") || 
			strings.Contains(output, `"enrolled":true`) || 
			strings.Contains(output, `"enrolled": true`)
			
		status.Validated = strings.Contains(output, "validated: true") || 
			strings.Contains(output, `"validated":true`) || 
			strings.Contains(output, `"validated": true`)
			
		status.Manual = strings.Contains(output, "manual: true") || 
			strings.Contains(output, `"manual":true`) || 
			strings.Contains(output, `"manual": true`)

		status.ConsoleManagement = strings.Contains(output, "console_management: true") ||
			strings.Contains(output, `"console_management":true`) ||
			strings.Contains(output, `"console_management": true`)
	}

	// Map fields if Enrolled/Validated are missing but other indicators are present
	// We DO NOT map status.Manual to status.Enrolled because 'manual' can be true even if not enrolled (default state).
	// User feedback indicates manual: true causes false positives.

	// If console management is enabled, it implies validation/connection
	if !status.Validated && status.ConsoleManagement {
		status.Validated = true
	}
	
	// If ConsoleManagement is true, it definitely means it is enrolled too
	if !status.Enrolled && status.ConsoleManagement {
		status.Enrolled = true
	}

	return status, nil
}
