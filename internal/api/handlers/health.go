package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// =============================================================================
// 1. HEALTH & DIAGNOSTICS
// =============================================================================
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
		if err == nil {
			// Parse bouncer JSON output
			if err := json.Unmarshal([]byte(bouncerOutput), &bouncers); err != nil {
				logger.Warn("Failed to parse bouncers JSON",
					"error", err,
					"output_length", len(bouncerOutput),
					"output_preview", truncateString(bouncerOutput, 100))
			} else {
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
				logger.Debug("Bouncers retrieved successfully", "count", len(bouncers))
			}
		} else {
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
