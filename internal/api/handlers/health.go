package handlers

import (
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// CheckCrowdSecHealth checks the health of the CrowdSec container and LAPI
func CheckCrowdSecHealth(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		logger.Info("Checking CrowdSec health")

		healthCheck := models.CrowdSecHealthCheck{
			Status: "healthy",
			Checks: make(map[string]models.HealthCheckItem),
		}

		isRunning, err := dockerClient.IsContainerRunning(cfg.CrowdsecContainerName)
		if err != nil || !isRunning {
			healthCheck.Status = "unhealthy"
			healthCheck.Checks["container"] = models.HealthCheckItem{
				Status:  "unhealthy",
				Message: "CrowdSec container is not running",
				Error:   fmt.Sprintf("%v", err),
			}
			c.JSON(http.StatusServiceUnavailable, models.Response{
				Success: false,
				Data:    healthCheck,
				Error:   "CrowdSec container is not running",
			})
			return
		}
		healthCheck.Checks["container"] = models.HealthCheckItem{
			Status:  "healthy",
			Message: "CrowdSec container is running",
		}

		lapiOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "lapi", "status"})
		if err != nil {
			healthCheck.Status = "degraded"
			healthCheck.Checks["lapi"] = models.HealthCheckItem{
				Status:  "unhealthy",
				Message: "LAPI status check failed",
				Error:   fmt.Sprintf("%v", err),
				Details: lapiOutput,
			}
		} else {
			if strings.Contains(strings.ToLower(lapiOutput), "successfully") ||
				strings.Contains(strings.ToLower(lapiOutput), "ok") {
				healthCheck.Checks["lapi"] = models.HealthCheckItem{
					Status:  "healthy",
					Message: "LAPI is reachable and responding",
					Details: lapiOutput,
				}
			} else {
				healthCheck.Status = "degraded"
				healthCheck.Checks["lapi"] = models.HealthCheckItem{
					Status:  "degraded",
					Message: "LAPI status unclear",
					Details: lapiOutput,
				}
			}
		}

		metricsItem := checkMetricsHealth(dockerClient, cfg.CrowdsecContainerName, cfg.CrowdSecMetricsURL)
		if metricsItem.Status == "unhealthy" {
			healthCheck.Status = "degraded"
		}
		healthCheck.Checks["metrics"] = metricsItem

		bouncersItem := checkBouncersHealth(dockerClient, cfg.CrowdsecContainerName)
		healthCheck.Checks["bouncers"] = bouncersItem

		consoleStatus, err := GetConsoleStatusHelper(dockerClient, cfg.CrowdsecContainerName)
		if err == nil {
			if consoleStatus.Enrolled && consoleStatus.Validated {
				healthCheck.Checks["console"] = models.HealthCheckItem{
					Status:  "healthy",
					Message: "Enrolled and validated with CrowdSec Console",
				}
			} else if consoleStatus.Enrolled {
				healthCheck.Checks["console"] = models.HealthCheckItem{
					Status:  "warning",
					Message: "Enrolled but not yet validated",
				}
			} else {
				healthCheck.Checks["console"] = models.HealthCheckItem{
					Status:  "info",
					Message: "Not enrolled with CrowdSec Console",
				}
			}
		}

		statusCode := http.StatusOK
		if healthCheck.Status == "unhealthy" {
			statusCode = http.StatusServiceUnavailable
		}

		c.JSON(statusCode, models.Response{
			Success: healthCheck.Status != "unhealthy",
			Data:    healthCheck,
			Message: fmt.Sprintf("CrowdSec health status: %s", healthCheck.Status),
		})
	}
}

// CheckStackHealth checks the health of all containers in the stack
func CheckStackHealth(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		logger.Info("Checking stack health")

		containers, allRunning := collectContainerHealth(dockerClient, cfg)

		healthStatus := models.HealthStatus{
			Containers: containers,
			AllRunning: allRunning,
			Timestamp:  time.Now(),
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    healthStatus,
			Message: fmt.Sprintf("Stack health check complete. All running: %v", allRunning),
		})
	}
}

// RunCompleteDiagnostics runs a complete system diagnostic
func RunCompleteDiagnostics(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		logger.Info("Running complete diagnostics")

		containers, allRunning := collectContainerHealth(dockerClient, cfg)
		healthStatus := &models.HealthStatus{
			Containers: containers,
			AllRunning: allRunning,
			Timestamp:  time.Now(),
		}

		var bouncers []models.Bouncer
		bouncerOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "bouncers", "list", "-o", "json"})
		if err == nil && bouncerOutput != "null" && bouncerOutput != "" && bouncerOutput != "[]" {
			parsed, parseErr := parseBouncersJSON(bouncerOutput, true)
			if parseErr != nil {
				logger.Warn("Failed to parse bouncers JSON",
					"error", parseErr,
					"output_length", len(bouncerOutput),
					"output_preview", truncateString(bouncerOutput, 100))
			} else {
				bouncers = parsed
				logger.Debug("Bouncers retrieved successfully", "count", len(bouncers))
			}
		} else if err != nil {
			logger.Warn("Failed to execute bouncers command", "error", err)
		}

		var decisions []models.Decision
		decisionOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "decisions", "list", "-o", "json"})
		if err == nil {
			parsed, parseErr := ParseDecisionsFromOutput(decisionOutput)
			if parseErr != nil {
				logger.Warn("Failed to parse decisions JSON", "error", parseErr)
			} else {
				decisions = parsed
				if len(decisions) > 0 {
					logger.Debug("Decisions retrieved successfully", "count", len(decisions))
				}
			}
		} else {
			logger.Warn("Failed to execute decisions command", "error", err)
		}

		result := models.DiagnosticResult{
			Health:    healthStatus,
			Bouncers:  bouncers,
			Decisions: decisions,
			Timestamp: time.Now(),
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    result,
			Message: "Complete diagnostics finished successfully",
		})
	}
}
