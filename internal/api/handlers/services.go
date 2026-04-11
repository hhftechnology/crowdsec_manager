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

// VerifyServices verifies all services are running
func VerifyServices(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		logger.Info("Verifying services")

		services := cfg.ServicesWithCrowdsec
		results := []gin.H{}

		for _, service := range services {
			isRunning, err := dockerClient.IsContainerRunning(service)
			result := gin.H{
				"name":    service,
				"running": isRunning,
			}
			if err != nil {
				result["error"] = err.Error()
			}
			results = append(results, result)
		}

		c.JSON(http.StatusOK, models.Response{Success: true, Data: results})
	}
}

// GracefulShutdown performs graceful shutdown of services
func GracefulShutdown(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		logger.Info("Performing graceful shutdown")

		services := make([]string, len(cfg.ServicesWithCrowdsec))
		copy(services, cfg.ServicesWithCrowdsec)

		for i, j := 0, len(services)-1; i < j; i, j = i+1, j-1 {
			services[i], services[j] = services[j], services[i]
		}

		for _, service := range services {
			logger.Info("Stopping service", "service", service)
			if err := dockerClient.StopContainerWithTimeout(service, 30); err != nil {
				logger.Error("Failed to stop service", "service", service, "error", err)
			}
		}

		c.JSON(http.StatusOK, models.Response{Success: true, Message: "Services shutdown successfully"})
	}
}

// ServiceAction performs start/stop/restart action on CrowdSec service only
func ServiceAction(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		var req models.ServiceAction
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid request: " + err.Error()})
			return
		}

		if req.Service != "crowdsec" && req.Service != cfg.CrowdsecContainerName {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Only crowdsec service is supported",
			})
			return
		}

		logger.Info("Performing service action", "service", req.Service, "action", req.Action)

		containerName := cfg.CrowdsecContainerName
		var err error
		switch req.Action {
		case "start":
			err = dockerClient.StartContainer(containerName)
		case "stop":
			err = dockerClient.StopContainerWithTimeout(containerName, 30)
		case "restart":
			err = dockerClient.RestartContainerWithTimeout(containerName, 30)
		default:
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid action. Must be start, stop, or restart"})
			return
		}

		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to %s service: %v", req.Action, err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("Service %s %sed successfully", containerName, req.Action),
		})
	}
}
