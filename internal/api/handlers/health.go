package handlers

import (
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"encoding/json" // Used for arbitrary JSON (metrics, raw decisions)
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/buger/jsonparser"
	"github.com/gin-gonic/gin"
)

// CheckCrowdSecHealth checks the health of the CrowdSec container and LAPI
func CheckCrowdSecHealth(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Checking CrowdSec health")

		healthCheck := models.CrowdSecHealthCheck{
			Status:    "healthy",
			Checks:    make(map[string]models.HealthCheckItem),
		}

		// 1. Check if CrowdSec container is running
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

		// 2. Check LAPI status
		lapiOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "lapi", "status",
		})
		if err != nil {
			healthCheck.Status = "degraded"
			healthCheck.Checks["lapi"] = models.HealthCheckItem{
				Status:  "unhealthy",
				Message: "LAPI status check failed",
				Error:   fmt.Sprintf("%v", err),
				Details: lapiOutput,
			}
		} else {
			// Check if LAPI is reachable in the output
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

		// 3. Check metrics availability
		// 3. Check metrics availability
		metricsOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "metrics", "-o", "json", "--url", "http://localhost:6060/metrics",
		})
		if err != nil {
			healthCheck.Status = "degraded"
			healthCheck.Checks["metrics"] = models.HealthCheckItem{
				Status:  "unhealthy",
				Message: "Metrics endpoint not accessible",
				Error:   fmt.Sprintf("%v", err),
			}
		} else {
			// Parse metrics JSON
			var metricsData map[string]interface{}
			if err := json.Unmarshal([]byte(metricsOutput), &metricsData); err == nil {
				healthCheck.Checks["metrics"] = models.HealthCheckItem{
					Status:  "healthy",
					Message: "Metrics endpoint is accessible",
					Metrics: metricsData,
				}
			} else {
				// Fallback if JSON parsing fails (or if output isn't JSON)
				healthCheck.Checks["metrics"] = models.HealthCheckItem{
					Status:  "healthy",
					Message: "Metrics endpoint is accessible (raw output)",
					Details: truncateString(metricsOutput, 200),
				}
			}
		}

		// 4. Check active bouncers
		bouncersOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "bouncers", "list", "-o", "json",
		})
		if err != nil {
			healthCheck.Checks["bouncers"] = models.HealthCheckItem{
				Status:  "degraded",
				Message: "Unable to retrieve bouncers list",
				Error:   fmt.Sprintf("%v", err),
			}
		} else {
			// Check if output is empty or null
			if bouncersOutput == "null" || bouncersOutput == "" || bouncersOutput == "[]" {
				healthCheck.Checks["bouncers"] = models.HealthCheckItem{
					Status:  "healthy",
					Message: "No bouncers registered",
					Details: "Active: 0, Total: 0",
				}
			} else {
				// Parse bouncers using jsonparser
				var bouncers []models.Bouncer
				dataBytes := []byte(bouncersOutput)

				_, err := jsonparser.ArrayEach(dataBytes, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
					var bouncer models.Bouncer

					if name, err := jsonparser.GetString(value, "name"); err == nil {
						bouncer.Name = name
					}
					if ipAddr, err := jsonparser.GetString(value, "ip_address"); err == nil {
						bouncer.IPAddress = ipAddr
					}
					if valid, err := jsonparser.GetBoolean(value, "valid"); err == nil {
						bouncer.Valid = valid
					}
					if lastPull, err := jsonparser.GetString(value, "last_pull"); err == nil {
						if t, err := time.Parse(time.RFC3339, lastPull); err == nil {
							bouncer.LastPull = t
						}
					}
					if bouncerType, err := jsonparser.GetString(value, "type"); err == nil {
						bouncer.Type = bouncerType
					}
					if version, err := jsonparser.GetString(value, "version"); err == nil {
						bouncer.Version = version
					}

					bouncers = append(bouncers, bouncer)
				})

				if err == nil {
					activeBouncers := 0
					for _, b := range bouncers {
						if time.Since(b.LastPull) <= 5*time.Minute {
							activeBouncers++
						}
					}
					healthCheck.Checks["bouncers"] = models.HealthCheckItem{
						Status:  "healthy",
						Message: fmt.Sprintf("%d active bouncer(s) out of %d total", activeBouncers, len(bouncers)),
						Details: fmt.Sprintf("Active: %d, Total: %d", activeBouncers, len(bouncers)),
					}
				} else {
					healthCheck.Checks["bouncers"] = models.HealthCheckItem{
						Status:  "degraded",
						Message: "Failed to parse bouncers data",
						Error:   fmt.Sprintf("%v", err),
					}
				}
			}
		}

		// 5. Check console enrollment status
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

		// Determine overall status code
		statusCode := http.StatusOK
		if healthCheck.Status == "unhealthy" {
			statusCode = http.StatusServiceUnavailable
		} else if healthCheck.Status == "degraded" {
			statusCode = http.StatusOK // Still return 200 for degraded
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
		logger.Info("Checking stack health")

		containerNames := []string{cfg.CrowdsecContainerName, cfg.TraefikContainerName, cfg.PangolinContainerName, cfg.GerbilContainerName}
		var containers []models.Container

		allRunning := true
		for _, name := range containerNames {
			containerID, err := dockerClient.GetContainerID(name)
			if err != nil {
				logger.Warn("Container not found", "name", name)
				containers = append(containers, models.Container{
					Name:    name,
					ID:      "",
					Status:  "not found",
					Running: false,
				})
				allRunning = false
				continue
			}

			isRunning, err := dockerClient.IsContainerRunning(name)
			if err != nil {
				logger.Error("Failed to check container status", "name", name, "error", err)
				containers = append(containers, models.Container{
					Name:    name,
					ID:      containerID,
					Status:  "error",
					Running: false,
				})
				allRunning = false
				continue
			}

			status := "stopped"
			if isRunning {
				status = "running"
			} else {
				allRunning = false
			}

			containers = append(containers, models.Container{
				Name:    name,
				ID:      containerID,
				Status:  status,
				Running: isRunning,
			})
		}

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
func RunCompleteDiagnostics(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Running complete diagnostics")

		// Get health status
		containerNames := []string{cfg.CrowdsecContainerName, cfg.TraefikContainerName, cfg.PangolinContainerName, cfg.GerbilContainerName}
		var containers []models.Container
		allRunning := true

		for _, name := range containerNames {
			containerID, err := dockerClient.GetContainerID(name)
			if err != nil {
				containers = append(containers, models.Container{
					Name:    name,
					Status:  "not found",
					Running: false,
				})
				allRunning = false
				continue
			}

			isRunning, _ := dockerClient.IsContainerRunning(name)
			status := "stopped"
			if isRunning {
				status = "running"
			} else {
				allRunning = false
			}

			containers = append(containers, models.Container{
				Name:    name,
				ID:      containerID,
				Status:  status,
				Running: isRunning,
			})
		}

		healthStatus := &models.HealthStatus{
			Containers: containers,
			AllRunning: allRunning,
			Timestamp:  time.Now(),
		}

		// Get bouncers
		var bouncers []models.Bouncer
		bouncerOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "bouncers", "list", "-o", "json"})
		if err == nil && bouncerOutput != "null" && bouncerOutput != "" && bouncerOutput != "[]" {
			// Parse bouncer JSON output using jsonparser
			dataBytes := []byte(bouncerOutput)

			_, parseErr := jsonparser.ArrayEach(dataBytes, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
				var bouncer models.Bouncer

				if name, err := jsonparser.GetString(value, "name"); err == nil {
					bouncer.Name = name
				}
				if ipAddr, err := jsonparser.GetString(value, "ip_address"); err == nil {
					bouncer.IPAddress = ipAddr
				}
				if valid, err := jsonparser.GetBoolean(value, "valid"); err == nil {
					bouncer.Valid = valid
				}
				if lastPull, err := jsonparser.GetString(value, "last_pull"); err == nil {
					if t, err := time.Parse(time.RFC3339, lastPull); err == nil {
						bouncer.LastPull = t
					}
				}
				if bouncerType, err := jsonparser.GetString(value, "type"); err == nil {
					bouncer.Type = bouncerType
				}
				if version, err := jsonparser.GetString(value, "version"); err == nil {
					bouncer.Version = version
				}

				// Compute status for each bouncer
				if time.Since(bouncer.LastPull) <= 5*time.Minute {
					bouncer.Status = "connected"
				} else if bouncer.Valid {
					bouncer.Status = "stale"
				} else {
					bouncer.Status = "disconnected"
				}

				bouncers = append(bouncers, bouncer)
			})

			if parseErr != nil {
				logger.Warn("Failed to parse bouncers JSON",
					"error", parseErr,
					"output_length", len(bouncerOutput),
					"output_preview", truncateString(bouncerOutput, 100))
			} else {
				logger.Debug("Bouncers retrieved successfully", "count", len(bouncers))
			}
		} else if err != nil {
			logger.Warn("Failed to execute bouncers command", "error", err)
		}

		// Get decisions
		var decisions []models.Decision
		decisionOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "decisions", "list", "-o", "json"})
		if err == nil {
			// Parse as raw JSON first to handle field name variations
			var rawDecisions []map[string]interface{}
			if err := json.Unmarshal([]byte(decisionOutput), &rawDecisions); err != nil {
				logger.Warn("Failed to parse decisions JSON",
					"error", err,
					"output_length", len(decisionOutput),
					"output_preview", truncateString(decisionOutput, 100))
			} else {
				// Convert to normalized Decision format
				decisions = make([]models.Decision, 0, len(rawDecisions))
				for _, raw := range rawDecisions {
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
				logger.Debug("Decisions retrieved successfully", "count", len(decisions))
			}
		} else {
			logger.Warn("Failed to execute decisions command", "error", err)
		}

		// Check Traefik integration
		traefikIntegration := &models.TraefikIntegration{
			MiddlewareConfigured: false,
			ConfigFiles:          []string{},
			LapiKeyFound:         false,
			AppsecEnabled:        false,
		}

		// Check multiple possible config files
		configPaths := []string{
			"/etc/traefik/dynamic_config.yml",
			"/etc/traefik/traefik_config.yml",
		}

		// Get dynamic config path from database if available
		if db != nil {
			if path, err := db.GetTraefikDynamicConfigPath(); err == nil {
				// Prepend database path to the beginning of the list
				configPaths = append([]string{path}, configPaths...)
			}
		}

		var configContent string
		var foundConfigPath string

		// Try each path until we find one that works
		for _, path := range configPaths {
			output, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{"cat", path})
			if err == nil && output != "" {
				configContent = output
				foundConfigPath = path
				break
			}
		}

		// Check for Traefik middleware configuration
		if configContent != "" {
			traefikIntegration.MiddlewareConfigured = true
			traefikIntegration.ConfigFiles = append(traefikIntegration.ConfigFiles, foundConfigPath)

			// Better detection logic - use case-insensitive matching
			configLower := strings.ToLower(configContent)

			// Check for LAPI key (bouncer plugin configuration)
			if strings.Contains(configLower, "crowdsec-bouncer-traefik-plugin") ||
				strings.Contains(configLower, "crowdseclapikey") ||
				strings.Contains(configLower, "crowdsec") {
				traefikIntegration.LapiKeyFound = true
			}

			// Check for AppSec
			if strings.Contains(configLower, "appsec") {
				traefikIntegration.AppsecEnabled = true
			}
		}

		result := models.DiagnosticResult{
			Health:             healthStatus,
			Bouncers:           bouncers,
			Decisions:          decisions,
			TraefikIntegration: traefikIntegration,
			Timestamp:          time.Now(),
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    result,
			Message: "Complete diagnostics finished successfully",
		})
	}
}
