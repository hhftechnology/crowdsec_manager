package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// =============================================================================
// DASHBOARD & METRICS
// =============================================================================

// GetBouncers retrieves CrowdSec bouncers
func GetBouncers(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec bouncers")

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "bouncers", "list", "-o", "json",
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get bouncers: %v", err),
			})
			return
		}

		// Parse the JSON to ensure it's valid and return as structured data
		var bouncers []models.Bouncer
		if err := json.Unmarshal([]byte(output), &bouncers); err != nil {
			// If JSON parsing fails, log details and return error
			logger.Warn("Failed to parse bouncers JSON",
				"error", err,
				"output_length", len(output),
				"output_preview", truncateString(output, 100))
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse bouncers JSON: %v", err),
			})
			return
		}

		// Compute status for each bouncer
		for i := range bouncers {
			// Primary indicator: if last pull was recent (within 5 minutes), bouncer is connected
			if time.Since(bouncers[i].LastPull) <= 5*time.Minute {
				bouncers[i].Status = "connected"
			} else if bouncers[i].Valid {
				// Last pull is old but key is valid - bouncer exists but inactive
				bouncers[i].Status = "stale"
			} else {
				// Key is invalid - bouncer is disconnected
				bouncers[i].Status = "disconnected"
			}
		}

		logger.Debug("Bouncers API retrieved successfully", "count", len(bouncers))

		// Return properly formatted data
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"bouncers": bouncers, "count": len(bouncers)},
		})
	}
}

// GetDecisions retrieves the list of active decisions
func GetDecisions(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec decisions")

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "decisions", "list", "-o", "json",
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get decisions: %v", err),
			})
			return
		}

		// Parse as raw JSON - CrowdSec returns an array of alert objects,
		// each containing a "decisions" array
		var rawAlerts []map[string]interface{}
		if err := json.Unmarshal([]byte(output), &rawAlerts); err != nil {
			// If JSON parsing fails, log details and return error
			logger.Warn("Failed to parse decisions JSON",
				"error", err,
				"output_length", len(output),
				"output_preview", truncateString(output, 100))
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse decisions JSON: %v", err),
			})
			return
		}

		// Extract decisions from each alert and convert to normalized Decision format
		decisions := make([]models.Decision, 0)
		for _, alert := range rawAlerts {
			// Each alert has a "decisions" array
			if decisionsArr, ok := alert["decisions"].([]interface{}); ok {
				for _, decisionInterface := range decisionsArr {
					if raw, ok := decisionInterface.(map[string]interface{}); ok {
						decision := models.Decision{
							ID:       int64(getInt(raw, "id")),
							Duration: getString(raw, "duration"),
						}

						// Handle origin/source field (CrowdSec might use either)
						decision.Source = getString(raw, "source")
						if decision.Source == "" {
							decision.Source = getString(raw, "origin")
						}
						decision.Origin = decision.Source

						// Handle type field
						decision.Type = getString(raw, "type")

						// Handle scope field
						decision.Scope = getString(raw, "scope")

						// Handle value field
						decision.Value = getString(raw, "value")

						// Handle scenario/reason field (CrowdSec might use either)
						decision.Scenario = getString(raw, "scenario")
						if decision.Scenario == "" {
							decision.Scenario = getString(raw, "reason")
						}
						decision.Reason = decision.Scenario

						// Handle created_at field
						decision.CreatedAt = getString(raw, "created_at")

						decisions = append(decisions, decision)
					}
				}
			}
		}

		logger.Debug("Decisions API retrieved successfully", "count", len(decisions))

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"decisions": decisions, "count": len(decisions)},
		})
	}
}

// GetMetrics retrieves CrowdSec Prometheus metrics
func GetMetrics(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec metrics")

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "metrics",
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get metrics: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"metrics": output},
		})
	}
}

// EnrollCrowdSec enrolls CrowdSec with the console
func EnrollCrowdSec(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			EnrollmentKey string `json:"enrollment_key" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Enrolling CrowdSec with console")

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "console", "enroll", req.EnrollmentKey,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to enroll: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "CrowdSec enrolled successfully",
			Data:    gin.H{"output": output},
		})
	}
}

// GetCrowdSecEnrollmentStatus checks the enrollment status
func GetCrowdSecEnrollmentStatus(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "console", "status", "-o", "json",
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to check status: %v", err),
			})
			return
		}

		// Parse JSON output
		// Example output: {"context":{},"enrolled":true,"manual":false,"validated":true}
		var status struct {
			Enrolled  bool `json:"enrolled"`
			Validated bool `json:"validated"`
		}
		if err := json.Unmarshal([]byte(output), &status); err != nil {
			logger.Warn("Failed to parse console status JSON", "error", err, "output", output)
			// Fallback to simple string check if JSON parsing fails
			status.Enrolled = strings.Contains(output, "enrolled: true")
			status.Validated = strings.Contains(output, "validated: true")
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    status,
		})
	}
}

// GetDecisionsAnalysis retrieves CrowdSec decisions with advanced filtering
func GetDecisionsAnalysis(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec decisions with filters")

		// Build command with filters from query parameters
		cmd := []string{"cscli", "decisions", "list", "-o", "json"}

		// Add time-based filters
		if since := c.Query("since"); since != "" {
			cmd = append(cmd, "--since", since)
		}
		if until := c.Query("until"); until != "" {
			cmd = append(cmd, "--until", until)
		}

		// Add decision type filter
		if decType := c.Query("type"); decType != "" && decType != "all" {
			cmd = append(cmd, "-t", decType)
		}

		// Add scope filter
		if scope := c.Query("scope"); scope != "" && scope != "all" {
			cmd = append(cmd, "--scope", scope)
		}

		// Add origin filter
		if origin := c.Query("origin"); origin != "" && origin != "all" {
			cmd = append(cmd, "--origin", origin)
		}

		// Add value filter
		if value := c.Query("value"); value != "" {
			cmd = append(cmd, "-v", value)
		}

		// Add scenario filter
		if scenario := c.Query("scenario"); scenario != "" {
			cmd = append(cmd, "-s", scenario)
		}

		// Add IP filter (shorthand for --scope ip --value <IP>)
		if ip := c.Query("ip"); ip != "" {
			cmd = append(cmd, "-i", ip)
		}

		// Add range filter (shorthand for --scope range --value <RANGE>)
		if ipRange := c.Query("range"); ipRange != "" {
			cmd = append(cmd, "-r", ipRange)
		}

		// Add --all flag to include decisions from Central API
		if includeAll := c.Query("includeAll"); includeAll == "true" {
			cmd = append(cmd, "-a")
		}

		logger.Debug("Executing decision analysis command", "cmd", cmd)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get decisions: %v", err),
			})
			return
		}

		// Log raw output for debugging
		logger.Debug("Raw decisions output",
			"length", len(output),
			"preview", truncateString(output, 200))

		// Parse as raw JSON - CrowdSec returns an array of alert objects,
		// each containing a "decisions" array
		var rawAlerts []map[string]interface{}
		if err := json.Unmarshal([]byte(output), &rawAlerts); err != nil {
			logger.Warn("Failed to parse decisions JSON",
				"error", err,
				"output_length", len(output),
				"output_preview", truncateString(output, 100))
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse decisions JSON: %v", err),
			})
			return
		}

		// Extract decisions from each alert and convert to normalized Decision format
		decisions := make([]models.Decision, 0)
		for _, alert := range rawAlerts {
			// Each alert has a "decisions" array
			if decisionsArr, ok := alert["decisions"].([]interface{}); ok {
				// Get alert-level created_at (decisions don't have their own created_at)
				alertCreatedAt := getString(alert, "created_at")
				
				for _, decisionInterface := range decisionsArr {
					if raw, ok := decisionInterface.(map[string]interface{}); ok {
						decision := models.Decision{
							ID:       int64(getInt(raw, "id")),
							Duration: getString(raw, "duration"),
						}

						// Handle origin/source field (CrowdSec might use either)
						decision.Source = getString(raw, "source")
						if decision.Source == "" {
							decision.Source = getString(raw, "origin")
						}
						decision.Origin = decision.Source

						// Handle type field
						decision.Type = getString(raw, "type")

						// Handle scope field
						decision.Scope = getString(raw, "scope")

						// Handle value field
						decision.Value = getString(raw, "value")

						// Handle scenario/reason field (CrowdSec might use either)
						decision.Scenario = getString(raw, "scenario")
						if decision.Scenario == "" {
							decision.Scenario = getString(raw, "reason")
						}
						decision.Reason = decision.Scenario

						// Use alert-level created_at (decisions inherit from their alert)
						decision.CreatedAt = alertCreatedAt

						// Calculate until/expires timestamp from created_at and duration
						if decision.CreatedAt != "" && decision.Duration != "" {
							if untilTime := calculateUntil(decision.CreatedAt, decision.Duration); untilTime != nil {
								decision.Until = untilTime.Format(time.RFC3339)
							}
						}

						decisions = append(decisions, decision)
					}
				}
			}
		}

		logger.Info("Decisions retrieved successfully",
			"count", len(decisions),
			"filters_applied", len(activeFilters(c)))

		// Return properly formatted data
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"decisions": decisions, "count": len(decisions)},
		})
	}
}

// GetAlertsAnalysis retrieves CrowdSec alerts with advanced filtering
func GetAlertsAnalysis(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec alerts with filters")

		// Build command with filters from query parameters
		cmd := []string{"cscli", "alerts", "list", "-o", "json"}

		// Add time-based filters
		if since := c.Query("since"); since != "" {
			cmd = append(cmd, "--since", since)
		}
		if until := c.Query("until"); until != "" {
			cmd = append(cmd, "--until", until)
		}

		// Add IP filter
		if ip := c.Query("ip"); ip != "" {
			cmd = append(cmd, "-i", ip)
		}

		// Add range filter
		if ipRange := c.Query("range"); ipRange != "" {
			cmd = append(cmd, "-r", ipRange)
		}

		// Add scope filter
		if scope := c.Query("scope"); scope != "" && scope != "all" {
			cmd = append(cmd, "--scope", scope)
		}

		// Add value filter
		if value := c.Query("value"); value != "" {
			cmd = append(cmd, "-v", value)
		}

		// Add scenario filter
		if scenario := c.Query("scenario"); scenario != "" {
			cmd = append(cmd, "-s", scenario)
		}

		// Add type filter (decision type associated with alert)
		if alertType := c.Query("type"); alertType != "" && alertType != "all" {
			cmd = append(cmd, "--type", alertType)
		}

		// Add origin filter
		if origin := c.Query("origin"); origin != "" && origin != "all" {
			cmd = append(cmd, "--origin", origin)
		}

		// Add --all flag to include alerts from Central API
		if includeAll := c.Query("includeAll"); includeAll == "true" {
			cmd = append(cmd, "-a")
		}

		logger.Debug("Executing alert analysis command", "cmd", cmd)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get alerts: %v", err),
			})
			return
		}

		// Parse the JSON output
		var alerts []interface{}
		if err := json.Unmarshal([]byte(output), &alerts); err != nil {
			logger.Warn("Failed to parse alerts JSON",
				"error", err,
				"output_length", len(output),
				"output_preview", truncateString(output, 100))
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse alerts JSON: %v", err),
			})
			return
		}

		logger.Debug("Alerts analysis retrieved successfully", "count", len(alerts))

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"alerts": alerts, "count": len(alerts)},
		})
	}
}
