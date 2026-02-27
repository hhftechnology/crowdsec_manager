package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"crowdsec-manager/internal/cache"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/buger/jsonparser"
	"github.com/gin-gonic/gin"
)

// =============================================================================
// DASHBOARD & METRICS
// =============================================================================

// GetDecisions retrieves CrowdSec decisions
func GetDecisions(dockerClient *docker.Client, cfg *config.Config, ttlCache ...*cache.TTLCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		// Check cache first
		summary := c.Query("summary") == "true"
		cacheKey := "decisions"
		if summary {
			cacheKey = "decisions-summary"
		}
		if len(ttlCache) > 0 && ttlCache[0] != nil {
			if cached, ok := ttlCache[0].Get(cacheKey); ok {
				c.JSON(http.StatusOK, models.Response{
					Success: true,
					Data:    cached,
				})
				return
			}
		}

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
			logger.Error("Failed to parse alerts JSON", "error", err, "output_preview", truncateString(output, 200))
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse decisions JSON: %v", err),
			})
			return
		}

		logger.Debug("Decisions retrieved successfully", "count", len(decisions))

		// Summary mode: return only count and lightweight aggregations
		if summary {
			typeDistribution := make(map[string]int)
			topScenarios := make(map[string]int)
			for _, d := range decisions {
				if d.Type != "" {
					typeDistribution[d.Type]++
				}
				if d.Scenario != "" {
					topScenarios[d.Scenario]++
				}
			}
			result := gin.H{
				"count":     len(decisions),
				"types":     typeDistribution,
				"scenarios": topScenarios,
			}
			if len(ttlCache) > 0 && ttlCache[0] != nil {
				ttlCache[0].Set(cacheKey, result, 15*time.Second)
			}
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    result,
			})
			return
		}

		result := gin.H{"decisions": decisions, "count": len(decisions)}
		if len(ttlCache) > 0 && ttlCache[0] != nil {
			ttlCache[0].Set(cacheKey, result, 15*time.Second)
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    result,
		})
	}
}

// GetMetrics retrieves CrowdSec metrics
func GetMetrics(dockerClient *docker.Client, cfg *config.Config, ttlCache ...*cache.TTLCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		cacheKey := "metrics"
		if len(ttlCache) > 0 && ttlCache[0] != nil {
			if cached, ok := ttlCache[0].Get(cacheKey); ok {
				c.JSON(http.StatusOK, models.Response{
					Success: true,
					Data:    cached,
				})
				return
			}
		}

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

		var metrics interface{}
		if err := json.Unmarshal([]byte(output), &metrics); err != nil {
			logger.Warn("Failed to parse metrics JSON", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse metrics JSON: %v", err),
			})
			return
		}

		if len(ttlCache) > 0 && ttlCache[0] != nil {
			ttlCache[0].Set(cacheKey, metrics, 30*time.Second)
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    metrics,
		})
	}
}

// EnrollCrowdSec enrolls CrowdSec with the console
func EnrollCrowdSec(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		var req struct {
			EnrollmentKey  string `json:"enrollment_key" binding:"required"`
			Name           string `json:"name"`
			DisableContext *bool  `json:"disable_context,omitempty"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Enrolling CrowdSec with console", "has_name", req.Name != "")

		settings, err := db.GetSettings()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to read settings: %v", err),
			})
			return
		}

		disableContext := settings.EnrollDisableContext
		if req.DisableContext != nil {
			disableContext = *req.DisableContext
			settings.EnrollDisableContext = disableContext
			if err := db.UpdateSettings(settings); err != nil {
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Failed to save enrollment preference: %v", err),
				})
				return
			}
		}

		// Build command with optional name parameter
		cmd := []string{"cscli", "console", "enroll"}
		if disableContext {
			cmd = append(cmd, "--disable", "context")
		}
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
			Message: fmt.Sprintf("Enrollment key submitted. Please approve the request in your CrowdSec Console at %s", cfg.CrowdSecConsoleURL),
			Data:    gin.H{"output": output, "disable_context": disableContext},
		})
	}
}

// GetCrowdSecEnrollmentStatus checks the enrollment status
func GetCrowdSecEnrollmentStatus(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		status, err := GetConsoleStatusHelper(dockerClient, cfg.CrowdsecContainerName)
		if err != nil {
			logger.Error("Failed to get console status", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to check status: %v", err),
			})
			return
		}

		logger.Info("Console status retrieved", "enrolled", status.Enrolled, "validated", status.Validated, "manual", status.Manual)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    status,
		})
	}
}

// FinalizeCrowdSecEnrollment restarts CrowdSec and re-reads console status
func FinalizeCrowdSecEnrollment(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		logger.Info("Finalizing CrowdSec enrollment", "container", cfg.CrowdsecContainerName)

		if err := dockerClient.RestartContainer(cfg.CrowdsecContainerName); err != nil {
			logger.Error("Failed to restart CrowdSec during enrollment finalize", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to restart CrowdSec: %v", err),
			})
			return
		}

		var (
			status  models.ConsoleStatus
			lastErr error
		)

		// Poll briefly because status can fail while container is still starting.
		for i := 0; i < 6; i++ {
			status, lastErr = GetConsoleStatusHelper(dockerClient, cfg.CrowdsecContainerName)
			if lastErr == nil {
				c.JSON(http.StatusOK, models.Response{
					Success: true,
					Message: "CrowdSec restarted and console status refreshed",
					Data:    status,
				})
				return
			}

			time.Sleep(2 * time.Second)
		}

		logger.Error("Failed to read console status after CrowdSec restart", "error", lastErr)
		c.JSON(http.StatusInternalServerError, models.Response{
			Success: false,
			Error:   fmt.Sprintf("CrowdSec restarted but status check failed: %v", lastErr),
		})
	}
}

// GetCrowdSecEnrollmentPreferences returns persisted enrollment preferences
func GetCrowdSecEnrollmentPreferences(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		settings, err := db.GetSettings()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to read settings: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: gin.H{
				"disable_context": settings.EnrollDisableContext,
			},
		})
	}
}

// UpdateCrowdSecEnrollmentPreferences updates persisted enrollment preferences
func UpdateCrowdSecEnrollmentPreferences(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			DisableContext bool `json:"disable_context"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		settings, err := db.GetSettings()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to read settings: %v", err),
			})
			return
		}

		settings.EnrollDisableContext = req.DisableContext
		if err := db.UpdateSettings(settings); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to save enrollment preference: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Enrollment preferences updated",
			Data: gin.H{
				"disable_context": settings.EnrollDisableContext,
			},
		})
	}
}
