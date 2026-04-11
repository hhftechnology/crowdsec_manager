package handlers

import (
	"encoding/json"
	"fmt"
	"strings"

	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/buger/jsonparser"
	"github.com/gin-gonic/gin"
)

// resolveDockerClient returns the per-request Docker client from gin.Context
// (set by DockerHostSelector middleware), falling back to the default client.
// The returned client is scoped to the request context so Docker operations
// are cancelled when the HTTP request is cancelled.
func resolveDockerClient(c *gin.Context, fallback *docker.Client) *docker.Client {
	dc := fallback
	if val, exists := c.Get("dockerClient"); exists {
		if client, ok := val.(*docker.Client); ok {
			dc = client
		}
	}
	return dc.WithContext(c.Request.Context())
}

// truncateString truncates a string to a maximum length for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "... (truncated)"
}

func parseCLIJSONToBytes(output string) ([]byte, error) {
	parsed, err := parseCLIJSONOutput(output)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(parsed)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal parsed CLI JSON: %w", err)
	}
	return data, nil
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
	dataBytes, parseErr := parseCLIJSONToBytes(output)
	if parseErr == nil {
		if err := json.Unmarshal(dataBytes, &status); err != nil {
			parseErr = err
		}
	}

	if parseErr != nil {
		logger.Warn("Failed to parse console status JSON, attempting fallback", "error", parseErr)

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

	// Normalized approval semantics across CrowdSec versions.
	// Some versions only expose manual/context/console_management in JSON output.
	status.Approved = status.ConsoleManagement ||
		(status.Manual && status.Context) ||
		status.Validated ||
		(status.Enrolled && status.Validated)

	status.ManagementEnabled = status.ConsoleManagement

	if status.Approved {
		// Keep legacy fields consistent for existing UI consumers.
		status.Enrolled = true
		status.Validated = true
	}

	switch {
	case status.ManagementEnabled:
		status.Phase = "management_enabled"
	case status.Approved:
		status.Phase = "approved"
	case status.Manual || status.Context:
		status.Phase = "pending_approval"
	default:
		status.Phase = "not_enrolled"
	}

	return status, nil
}

// parseDecisionNode extracts a models.Decision from a jsonparser byte slice.
// Used by both GetDecisions and GetDecisionsAnalysis to avoid duplicating
// field-extraction logic.
func parseDecisionNode(data []byte) models.Decision {
	var d models.Decision
	if id, err := jsonparser.GetInt(data, "id"); err == nil {
		d.ID = id
	}
	if v, err := jsonparser.GetString(data, "origin"); err == nil {
		d.Origin = v
	}
	if v, err := jsonparser.GetString(data, "type"); err == nil {
		d.Type = v
	}
	if v, err := jsonparser.GetString(data, "scope"); err == nil {
		d.Scope = v
	}
	if v, err := jsonparser.GetString(data, "value"); err == nil {
		d.Value = v
	}
	if v, err := jsonparser.GetString(data, "duration"); err == nil {
		d.Duration = v
	}
	if v, err := jsonparser.GetString(data, "scenario"); err == nil {
		d.Scenario = v
	}
	if v, err := jsonparser.GetBoolean(data, "simulated"); err == nil {
		d.Simulated = v
	}
	if v, err := jsonparser.GetString(data, "created_at"); err == nil {
		d.CreatedAt = v
	}
	return d
}

// ParseDecisionsFromOutput parses the raw JSON output of cscli decisions list
// and extracts the nested decisions effectively.
func ParseDecisionsFromOutput(output string) ([]models.Decision, error) {
	// Parse alerts using normalized CLI JSON output.
	var decisions []models.Decision
	dataBytes, parseErr := parseCLIJSONToBytes(output)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to normalize decisions JSON: %w", parseErr)
	}

	_, err := jsonparser.ArrayEach(dataBytes, func(alertValue []byte, alertType jsonparser.ValueType, alertOffset int, alertErr error) {
		// Get alert's created_at for fallback
		var alertCreatedAt string
		if createdAt, err := jsonparser.GetString(alertValue, "created_at"); err == nil {
			alertCreatedAt = createdAt
		}

		// Get alert's ID
		var alertID int64
		if id, err := jsonparser.GetInt(alertValue, "id"); err == nil {
			alertID = id
		}

		// Parse decisions array within this alert
		foundNested := false
		jsonparser.ArrayEach(alertValue, func(decisionValue []byte, decisionType jsonparser.ValueType, decisionOffset int, decisionErr error) {
			foundNested = true
			decision := parseDecisionNode(decisionValue)
			if decision.CreatedAt == "" {
				decision.CreatedAt = alertCreatedAt
			}
			decision.AlertID = alertID
			decisions = append(decisions, decision)
		}, "decisions")

		// Fallback: if no nested decisions found, check if the top-level
		// item itself has decision fields (manual decisions via cscli decisions add)
		if !foundNested {
			if _, _, _, err := jsonparser.Get(alertValue, "type"); err == nil {
				decision := parseDecisionNode(alertValue)
				if decision.CreatedAt == "" {
					decision.CreatedAt = alertCreatedAt
				}
				decision.AlertID = alertID
				decisions = append(decisions, decision)
			}
		}
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse alerts JSON: %w", err)
	}

	return decisions, nil
}

// CLIFlag represents a CLI flag and its value for building cscli commands.
type CLIFlag struct {
	Flag  string
	Value string
}

// appendCLIFlags appends non-empty flag/value pairs to a command slice.
// Returns the extended command and the number of flags added.
func appendCLIFlags(cmd []string, flags []CLIFlag) ([]string, int) {
	count := 0
	for _, f := range flags {
		if f.Value != "" {
			cmd = append(cmd, f.Flag, f.Value)
			count++
		}
	}
	return cmd, count
}

