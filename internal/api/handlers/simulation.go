package handlers

import (
	"fmt"
	"net/http"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// GetSimulationStatus gets the current simulation configuration
func GetSimulationStatus(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		cmd := []string{"cscli", "simulation", "status", "-o", "json"}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to get simulation status", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get simulation status: %v", err),
			})
			return
		}

		parsed, err := parseCLIJSONOutput(output)
		if err != nil {
			logger.Warn("Failed to parse simulation status JSON, returning raw", "error", err)
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    output,
				Message: "Simulation status retrieved (raw format)",
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    parsed,
			Message: "Simulation status retrieved successfully",
		})
	}
}

// ToggleSimulation enables or disables simulation for a scenario
func ToggleSimulation(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		var req models.SimulationRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		// Validate scenario name to prevent injection
		if !validateHubItemName(req.Scenario) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid scenario name",
			})
			return
		}

		action := "disable"
		if req.Enabled {
			action = "enable"
		}

		cmd := []string{"cscli", "simulation", action, req.Scenario}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to toggle simulation", "scenario", req.Scenario, "action", action, "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to %s simulation for %s: %v", action, req.Scenario, err),
			})
			return
		}

		logger.Info("Simulation toggled", "scenario", req.Scenario, "action", action)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    output,
			Message: fmt.Sprintf("Simulation %sd for scenario: %s", action, req.Scenario),
		})
	}
}
