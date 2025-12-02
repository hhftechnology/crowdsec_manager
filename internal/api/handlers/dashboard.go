package handlers

import (
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"encoding/json" // Used for arbitrary JSON in GetMetrics
	"fmt"
	"net/http"
	"strings"

	"github.com/buger/jsonparser"
	"github.com/gin-gonic/gin"
)

// =============================================================================
// DASHBOARD & METRICS
// =============================================================================

// GetDecisions retrieves CrowdSec decisions
// GetDecisions retrieves CrowdSec decisions
func GetDecisions(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec decisions via cscli")

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

		// Check if output is empty or null
		if output == "null" || output == "" || output == "[]" {
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    gin.H{"decisions": []models.Decision{}, "count": 0},
			})
			return
		}

		// Parse alerts using jsonparser
		var decisions []models.Decision
		dataBytes := []byte(output)

		_, err = jsonparser.ArrayEach(dataBytes, func(alertValue []byte, alertType jsonparser.ValueType, alertOffset int, alertErr error) {
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
			jsonparser.ArrayEach(alertValue, func(decisionValue []byte, decisionType jsonparser.ValueType, decisionOffset int, decisionErr error) {
				var decision models.Decision

				// Extract decision fields
				if id, err := jsonparser.GetInt(decisionValue, "id"); err == nil {
					decision.ID = id
				}
				if origin, err := jsonparser.GetString(decisionValue, "origin"); err == nil {
					decision.Origin = origin
				}
				if decisionType, err := jsonparser.GetString(decisionValue, "type"); err == nil {
					decision.Type = decisionType
				}
				if scope, err := jsonparser.GetString(decisionValue, "scope"); err == nil {
					decision.Scope = scope
				}
				if value, err := jsonparser.GetString(decisionValue, "value"); err == nil {
					decision.Value = value
				}
				if duration, err := jsonparser.GetString(decisionValue, "duration"); err == nil {
					decision.Duration = duration
				}
				if scenario, err := jsonparser.GetString(decisionValue, "scenario"); err == nil {
					decision.Scenario = scenario
				}
				if simulated, err := jsonparser.GetBoolean(decisionValue, "simulated"); err == nil {
					decision.Simulated = simulated
				}
				if createdAt, err := jsonparser.GetString(decisionValue, "created_at"); err == nil {
					decision.CreatedAt = createdAt
				}

				// Set created_at from alert if not present in decision
				if decision.CreatedAt == "" {
					decision.CreatedAt = alertCreatedAt
				}

				// Set AlertID
				decision.AlertID = alertID

				decisions = append(decisions, decision)
			}, "decisions")
		})

		if err != nil {
			logger.Error("Failed to parse alerts JSON", "error", err, "output_preview", truncateString(output, 200))
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse decisions JSON: %v", err),
			})
			return
		}

		logger.Debug("Decisions retrieved successfully", "count", len(decisions))

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"decisions": decisions, "count": len(decisions)},
		})
	}
}

// GetMetrics retrieves CrowdSec metrics
// GetMetrics retrieves CrowdSec metrics
func GetMetrics(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec metrics")

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "metrics", "-o", "json",
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get metrics: %v", err),
			})
			return
		}

		// Parse as raw JSON
		var metrics interface{}
		if err := json.Unmarshal([]byte(output), &metrics); err != nil {
			logger.Warn("Failed to parse metrics JSON", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse metrics JSON: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    metrics,
		})
	}
}

// EnrollCrowdSec enrolls CrowdSec with the console
func EnrollCrowdSec(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			EnrollmentKey string `json:"enrollment_key" binding:"required"`
			Name          string `json:"name"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Enrolling CrowdSec with console", "has_name", req.Name != "")

		// Build command with optional name parameter
		cmd := []string{"cscli", "console", "enroll"}
		if req.Name != "" {
			cmd = append(cmd, "--name", req.Name)
		}
		cmd = append(cmd, req.EnrollmentKey)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Enrollment command failed", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to enroll: %v", err),
			})
			return
		}

		// Log the full output for debugging
		logger.Info("Enrollment command completed", "output", output)

		// Check if output indicates success or failure
		outputLower := strings.ToLower(output)
		if strings.Contains(outputLower, "error") || strings.Contains(outputLower, "failed") || strings.Contains(outputLower, "fatal") {
			logger.Warn("Enrollment may have failed", "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Enrollment failed: %s", output),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Enrollment key submitted. Please approve the request in your CrowdSec Console at https://app.crowdsec.net/",
			Data:    gin.H{"output": output},
		})
	}
}

// GetCrowdSecEnrollmentStatus checks the enrollment status
func GetCrowdSecEnrollmentStatus(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		status, err := GetConsoleStatusHelper(dockerClient, cfg.CrowdsecContainerName)
		if err != nil {
			logger.Error("Failed to get console status", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to check status: %v", err),
			})
			return
		}

		logger.Debug("Console status retrieved", "enrolled", status.Enrolled, "validated", status.Validated, "manual", status.Manual)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    status,
		})
	}
}

// GetDecisionsAnalysis retrieves CrowdSec decisions with advanced filtering
func GetDecisionsAnalysis(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec decisions analysis via cscli")

		cmd := []string{"cscli", "decisions", "list", "-o", "json"}

		// Add filters based on query parameters
		if v := c.Query("ip"); v != "" {
			cmd = append(cmd, "--ip", v)
		}
		if v := c.Query("range"); v != "" {
			cmd = append(cmd, "--range", v)
		}
		if v := c.Query("type"); v != "" && v != "all" {
			cmd = append(cmd, "--type", v)
		}
		if v := c.Query("scope"); v != "" && v != "all" {
			cmd = append(cmd, "--scope", v)
		}
		if v := c.Query("value"); v != "" {
			cmd = append(cmd, "--value", v)
		}
		if v := c.Query("scenario"); v != "" {
			cmd = append(cmd, "--scenario", v)
		}
		if v := c.Query("origin"); v != "" && v != "all" {
			cmd = append(cmd, "--origin", v)
		}
		if v := c.Query("until"); v != "" {
			cmd = append(cmd, "--until", v)
		}
		if v := c.Query("includeAll"); v == "true" {
			cmd = append(cmd, "-a")
		}

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get decisions analysis: %v", err),
			})
			return
		}

		// Check if output is empty or null
		if output == "null" || output == "" || output == "[]" {
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    gin.H{"decisions": []models.Decision{}, "count": 0},
			})
			return
		}

		// Parse alerts using jsonparser
		var decisions []models.Decision
		dataBytes := []byte(output)

		_, err = jsonparser.ArrayEach(dataBytes, func(alertValue []byte, alertType jsonparser.ValueType, alertOffset int, alertErr error) {
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
			jsonparser.ArrayEach(alertValue, func(decisionValue []byte, decisionType jsonparser.ValueType, decisionOffset int, decisionErr error) {
				var decision models.Decision

				// Extract decision fields
				if id, err := jsonparser.GetInt(decisionValue, "id"); err == nil {
					decision.ID = id
				}
				if origin, err := jsonparser.GetString(decisionValue, "origin"); err == nil {
					decision.Origin = origin
				}
				if decisionType, err := jsonparser.GetString(decisionValue, "type"); err == nil {
					decision.Type = decisionType
				}
				if scope, err := jsonparser.GetString(decisionValue, "scope"); err == nil {
					decision.Scope = scope
				}
				if value, err := jsonparser.GetString(decisionValue, "value"); err == nil {
					decision.Value = value
				}
				if duration, err := jsonparser.GetString(decisionValue, "duration"); err == nil {
					decision.Duration = duration
				}
				if scenario, err := jsonparser.GetString(decisionValue, "scenario"); err == nil {
					decision.Scenario = scenario
				}
				if simulated, err := jsonparser.GetBoolean(decisionValue, "simulated"); err == nil {
					decision.Simulated = simulated
				}
				if createdAt, err := jsonparser.GetString(decisionValue, "created_at"); err == nil {
					decision.CreatedAt = createdAt
				}

				// Set created_at from alert if not present in decision
				if decision.CreatedAt == "" {
					decision.CreatedAt = alertCreatedAt
				}

				// Set AlertID
				decision.AlertID = alertID

				decisions = append(decisions, decision)
			}, "decisions")
		})

		if err != nil {
			logger.Error("Failed to parse decisions analysis JSON", "error", err, "output_preview", truncateString(output, 200))
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse decisions JSON: %v", err),
			})
			return
		}
	

		logger.Info("Decisions analysis retrieved successfully",
			"count", len(decisions),
			"cmd", cmd)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"decisions": decisions, "count": len(decisions)},
		})
	}
}

// GetAlertsAnalysis retrieves CrowdSec alerts with advanced filtering
func GetAlertsAnalysis(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec alerts analysis via cscli")

		cmd := []string{"cscli", "alerts", "list", "-o", "json"}

		// Add filters based on query parameters
		// Add filters based on query parameters
		if v := c.Query("id"); v != "" {
			cmd = append(cmd, "--id", v)
		}
		if v := c.Query("ip"); v != "" {
			cmd = append(cmd, "--ip", v)
		}
		if v := c.Query("range"); v != "" {
			cmd = append(cmd, "--range", v)
		}
		if v := c.Query("type"); v != "" && v != "all" {
			cmd = append(cmd, "--type", v)
		}
		if v := c.Query("scope"); v != "" && v != "all" {
			cmd = append(cmd, "--scope", v)
		}
		if v := c.Query("value"); v != "" {
			cmd = append(cmd, "--value", v)
		}
		if v := c.Query("scenario"); v != "" {
			cmd = append(cmd, "--scenario", v)
		}
		if v := c.Query("origin"); v != "" && v != "all" {
			cmd = append(cmd, "--origin", v)
		}
		if v := c.Query("since"); v != "" {
			cmd = append(cmd, "--since", v)
		}
		if v := c.Query("until"); v != "" {
			cmd = append(cmd, "--until", v)
		}
		if v := c.Query("includeAll"); v == "true" {
			cmd = append(cmd, "-a")
		}
		
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to get alerts analysis", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get alerts: %v", err),
			})
			return
		}

		// Parse JSON
		var alerts []interface{} // Using interface{} for now as Alert model might need adjustment
		if err := json.Unmarshal([]byte(output), &alerts); err != nil {
			if output == "null" || output == "" {
				c.JSON(http.StatusOK, models.Response{
					Success: true,
					Data:    gin.H{"alerts": []interface{}{}, "count": 0},
				})
				return
			}
			
			logger.Warn("Failed to parse alerts JSON", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse alerts: %v", err),
			})
			return
		}

		logger.Info("Alerts analysis retrieved successfully", "count", len(alerts))

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"alerts": alerts, "count": len(alerts)},
		})
	}
}


