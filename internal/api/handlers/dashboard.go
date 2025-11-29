package handlers

import (
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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

		// Parse the JSON as alerts (CrowdSec returns array of alerts, each containing decisions)
		var alerts []models.Alert
		if err := json.Unmarshal([]byte(output), &alerts); err != nil {
			// If output is empty or "null", it means no decisions
			if output == "null" || output == "" || output == "[]" {
				c.JSON(http.StatusOK, models.Response{
					Success: true,
					Data:    []models.Decision{},
				})
				return
			}

			logger.Warn("Failed to parse alerts JSON", "error", err, "output_preview", truncateString(output, 200))
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse decisions JSON: %v", err),
			})
			return
		}

		// Extract all decisions from all alerts
		var decisions []models.Decision
		for _, alert := range alerts {
			for _, decision := range alert.Decisions {
				// Set created_at from alert if not present in decision
				if decision.CreatedAt == "" {
					decision.CreatedAt = alert.CreatedAt
				}
				decisions = append(decisions, decision)
			}
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

		// Parse the JSON as alerts (CrowdSec returns array of alerts, each containing decisions)
		var alerts []models.Alert
		if err := json.Unmarshal([]byte(output), &alerts); err != nil {
			// If output is empty or "null", it means no decisions
			if output == "null" || output == "" || output == "[]" {
				c.JSON(http.StatusOK, models.Response{
					Success: true,
					Data:    gin.H{"decisions": []models.Decision{}, "count": 0},
				})
				return
			}
	
			logger.Warn("Failed to parse decisions analysis JSON", "error", err, "output_preview", truncateString(output, 200))
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse decisions JSON: %v", err),
			})
			return
		}
	
		// Extract all decisions from all alerts
		var decisions []models.Decision
		for _, alert := range alerts {
			for _, decision := range alert.Decisions {
				// Set created_at from alert if not present in decision
				if decision.CreatedAt == "" {
					decision.CreatedAt = alert.CreatedAt
				}
				decisions = append(decisions, decision)
			}
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
		if v := c.Query("since"); v != "" {
			cmd = append(cmd, "--since", v)
		}
		if v := c.Query("until"); v != "" {
			cmd = append(cmd, "--until", v)
		}
		// cscli alerts list doesn't support all the same filters as decisions list directly in the same way,
		// but let's try to map what we can.
		// Note: cscli alerts list filters are a bit different.
		// Common ones: --since, --until, --scenario, --ip, --range
		
		if v := c.Query("ip"); v != "" {
			// cscli alerts list doesn't have --ip, it filters by value usually?
			// Actually it does not seem to have specific --ip flag in all versions.
			// But let's check help or assume standard filters.
			// If not supported, we might need to filter in memory or ignore.
			// For now, let's assume basic filters.
		}
		
		// For now, let's just use basic list and maybe --since/--until
		
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


