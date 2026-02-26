package handlers

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/constants"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parseHumanReadableScenarios parses the human-readable table format
func parseHumanReadableScenarios(output string) []gin.H {
	scenarios := []gin.H{}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines, headers, and separator lines
		if line == "" ||
			strings.Contains(line, "─") ||
			strings.Contains(line, "SCENARIOS") ||
			strings.Contains(line, "Name") ||
			strings.Contains(line, "📦 Status") {
			continue
		}

		// Remove leading/trailing pipes if present
		line = strings.Trim(line, "│ ")

		// Split by multiple spaces (table columns)
		parts := strings.Fields(line)

		if len(parts) >= 2 {
			scenario := gin.H{
				"name": parts[0],
			}

			// Parse status
			if len(parts) >= 2 {
				if strings.Contains(parts[1], "enabled") || parts[1] == "✔️" {
					scenario["status"] = "enabled"
				} else {
					scenario["status"] = parts[1]
				}
			}

			// Parse version
			if len(parts) >= 3 {
				scenario["version"] = parts[2]
			}

			// Parse local path (join remaining parts)
			if len(parts) >= 4 {
				scenario["local_path"] = strings.Join(parts[3:], " ")
			}

			scenarios = append(scenarios, scenario)
		}
	}

	return scenarios
}

// GetScenarioFiles returns a list of scenario files from the host filesystem
func GetScenarioFiles(configDir string) gin.HandlerFunc {
	return func(c *gin.Context) {
		hostScenariosDir := filepath.Join(configDir, constants.CrowdSecConfigSubdir, "scenarios")

		if _, err := os.Stat(hostScenariosDir); os.IsNotExist(err) {
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    []string{},
				Message: "No scenarios directory found",
			})
			return
		}

		entries, err := os.ReadDir(hostScenariosDir)
		if err != nil {
			logger.Error("Failed to read scenarios directory", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to read scenarios directory: %v", err),
			})
			return
		}

		scenarioFiles := []gin.H{}
		for _, entry := range entries {
			if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
				continue
			}

			filePath := filepath.Join(hostScenariosDir, entry.Name())
			info, err := entry.Info()
			if err != nil {
				continue
			}

			content, err := os.ReadFile(filePath)
			if err != nil {
				logger.Warn("Failed to read scenario file", "file", entry.Name(), "error", err)
				continue
			}

			var scenarioData map[string]any
			if err := yaml.Unmarshal(content, &scenarioData); err == nil {
				scenarioFiles = append(scenarioFiles, gin.H{
					"filename":    entry.Name(),
					"name":        scenarioData["name"],
					"description": scenarioData["description"],
					"type":        scenarioData["type"],
					"size":        info.Size(),
					"modified":    info.ModTime(),
				})
			} else {
				scenarioFiles = append(scenarioFiles, gin.H{
					"filename": entry.Name(),
					"size":     info.Size(),
					"modified": info.ModTime(),
				})
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    scenarioFiles,
			Message: fmt.Sprintf("Found %d scenario files", len(scenarioFiles)),
		})
	}
}

// DeleteScenarioFile deletes a scenario file from the host filesystem
func DeleteScenarioFile(dockerClient *docker.Client, configDir string, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		var req struct {
			Filename string `json:"filename" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		if strings.Contains(req.Filename, "..") || strings.Contains(req.Filename, "/") {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid filename",
			})
			return
		}

		hostScenariosDir := filepath.Join(configDir, constants.CrowdSecConfigSubdir, "scenarios")
		filePath := filepath.Join(hostScenariosDir, req.Filename)

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, models.Response{
				Success: false,
				Error:   "Scenario file not found",
			})
			return
		}

		if err := os.Remove(filePath); err != nil {
			logger.Error("Failed to delete scenario file", "file", req.Filename, "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to delete scenario file: %v", err),
			})
			return
		}

		logger.Info("Scenario file deleted", "file", req.Filename)

		logger.Info("Restarting CrowdSec to apply changes")
		if err := dockerClient.RestartContainerWithTimeout(cfg.CrowdsecContainerName, 30); err != nil {
			logger.Warn("Failed to restart CrowdSec after deleting scenario", "error", err)
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Scenario file deleted successfully",
		})
	}
}
