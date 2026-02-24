package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/constants"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// =============================================================================
// 4. SCENARIOS
// =============================================================================

// SetupCustomScenarios installs custom CrowdSec scenarios
func SetupCustomScenarios(dockerClient *docker.Client, configDir string, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		var req models.ScenarioSetupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Setting up custom scenarios", "count", len(req.Scenarios))

		hostScenariosDir := filepath.Join(configDir, constants.CrowdSecConfigSubdir, "scenarios")

		if err := os.MkdirAll(hostScenariosDir, 0755); err != nil {
			logger.Error("Failed to create scenarios directory on host", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to create scenarios directory: %v", err),
			})
			return
		}

		results := []gin.H{}
		hasErrors := false

		for _, scenario := range req.Scenarios {
			// Validate YAML content
			var temp interface{}
			if err := yaml.Unmarshal([]byte(scenario.Content), &temp); err != nil {
				result := gin.H{
					"name":    scenario.Name,
					"success": false,
					"error":   fmt.Sprintf("Invalid YAML content: %v", err),
				}
				results = append(results, result)
				hasErrors = true
				logger.Error("Invalid YAML content for scenario", "name", scenario.Name, "error", err)
				continue
			}

			filename := strings.ReplaceAll(scenario.Name, "/", "_") + ".yaml"
			hostScenarioPath := filepath.Join(hostScenariosDir, filename)
			containerScenarioPath := filepath.Join(cfg.CrowdSecScenariosDir, filename)

			logger.Debug("Writing scenario file",
				"name", scenario.Name,
				"host_path", hostScenarioPath,
				"container_path", containerScenarioPath)

			if err := os.WriteFile(hostScenarioPath, []byte(scenario.Content), 0644); err != nil {
				result := gin.H{
					"name":    scenario.Name,
					"success": false,
					"path":    hostScenarioPath,
					"error":   err.Error(),
				}
				results = append(results, result)
				hasErrors = true
				logger.Error("Failed to write scenario file to host", "name", scenario.Name, "error", err)
				continue
			}

			fileExists, err := dockerClient.FileExists(cfg.CrowdsecContainerName, containerScenarioPath)

			result := gin.H{
				"name":           scenario.Name,
				"success":        true,
				"host_path":      hostScenarioPath,
				"container_path": containerScenarioPath,
				"verified":       fileExists,
			}

			if err != nil || !fileExists {
				result["warning"] = "File written to host but not visible in container. Check volume mount."
				logger.Warn("Scenario file not visible in container",
					"name", scenario.Name,
					"verify_error", err,
					"file_exists", fileExists)
			}

			results = append(results, result)
			logger.Info("Successfully wrote scenario file", "name", scenario.Name, "path", hostScenarioPath)
		}

		if !hasErrors && len(req.Scenarios) > 0 {
			logger.Info("Restarting CrowdSec to load new scenarios")

			restartOutput, restartErr := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"kill", "-SIGHUP", "1"})

			if restartErr != nil {
				logger.Warn("Failed to send HUP signal to CrowdSec, attempting container restart", "error", restartErr)

				if err := dockerClient.RestartContainerWithTimeout(cfg.CrowdsecContainerName, 30); err != nil {
					logger.Error("Failed to restart CrowdSec container", "error", err)
					c.JSON(http.StatusOK, models.Response{
						Success: false,
						Message: "Scenarios written but failed to restart CrowdSec",
						Data:    results,
						Error:   fmt.Sprintf("Restart failed: %v", err),
					})
					return
				}

				logger.Info("CrowdSec container restarted successfully")
			} else {
				logger.Debug("CrowdSec reload signal sent", "output", restartOutput)
			}

			time.Sleep(2 * time.Second)
		}

		c.JSON(http.StatusOK, models.Response{
			Success: !hasErrors,
			Message: "Custom scenarios setup completed",
			Data:    results,
		})
	}
}

// ListScenarios lists all installed CrowdSec scenarios
func ListScenarios(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		logger.Info("Listing scenarios")

		// Try JSON format first
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "scenarios", "list", "-o", "json",
		})

		if err != nil {
			logger.Error("Failed to list scenarios", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to list scenarios: %v", err),
			})
			return
		}

		// Clean the output - remove any non-JSON characters
		cleanedOutput := strings.TrimSpace(output)

		// Define structs for parsing
		type ScenarioItem struct {
			Name         string `json:"name"`
			Description  string `json:"description"`
			Status       string `json:"status"`
			Version      string `json:"version"`
			LocalVersion string `json:"local_version"`
			LocalPath    string `json:"local_path"`
			Installed    bool   `json:"installed"`
		}

		type ScenariosResponse struct {
			Scenarios []ScenarioItem `json:"scenarios"`
		}

		var installedScenarios []ScenarioItem

		// Try parsing as nested structure {"scenarios": [...]}
		var scenariosResp ScenariosResponse
		if err := json.Unmarshal([]byte(cleanedOutput), &scenariosResp); err == nil && len(scenariosResp.Scenarios) > 0 {
			installedScenarios = scenariosResp.Scenarios
		} else {
			// Fallback: try parsing as flat array
			var flatScenarios []ScenarioItem
			if err := json.Unmarshal([]byte(cleanedOutput), &flatScenarios); err == nil {
				installedScenarios = flatScenarios
			}
		}

		// Filter for installed scenarios if we found any
		if len(installedScenarios) > 0 {
			filteredScenarios := []ScenarioItem{}
			for _, s := range installedScenarios {
				// Check if installed
				isInstalled := s.Installed || s.LocalPath != "" || s.LocalVersion != "" || s.Status == "enabled"
				if isInstalled {
					filteredScenarios = append(filteredScenarios, s)
				}
			}

			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Message: fmt.Sprintf("Found %d installed scenarios", len(filteredScenarios)),
				Data: gin.H{
					"scenarios": filteredScenarios,
					"count":     len(filteredScenarios),
				},
			})
			return
		}

		// JSON parsing failed or returned empty, try text format
		logger.Warn("Failed to parse scenarios as JSON or empty result", "error", err, "trying_text_format", true)

		// Fallback to text parsing
		scenarios := parseHumanReadableScenarios(output)

		if len(scenarios) > 0 {
			logger.Info("Successfully parsed scenarios from human format", "count", len(scenarios))
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Message: fmt.Sprintf("Found %d scenarios (parsed from text)", len(scenarios)),
				Data: gin.H{
					"scenarios": scenarios,
					"count":     len(scenarios),
				},
			})
			return
		}

		c.JSON(http.StatusInternalServerError, models.Response{
			Success: false,
			Error:   "Failed to parse scenarios output",
			Data: gin.H{
				"raw_output_preview": truncateString(output, 500),
			},
		})
	}
}
