package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/traefikconfig"

	"github.com/gin-gonic/gin"
)

// =============================================================================
// SERVICES
// =============================================================================

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

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    results,
		})
	}
}

// GracefulShutdown performs graceful shutdown of services
func GracefulShutdown(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		logger.Info("Performing graceful shutdown")

		// Shutdown in reverse order of startup (roughly)
		services := make([]string, len(cfg.ServicesWithCrowdsec))
		copy(services, cfg.ServicesWithCrowdsec)

		// Reverse the slice for shutdown
		for i, j := 0, len(services)-1; i < j; i, j = i+1, j-1 {
			services[i], services[j] = services[j], services[i]
		}

		for _, service := range services {
			logger.Info("Stopping service", "service", service)
			if service == cfg.TraefikContainerName {
				if err := dockerClient.StopContainerWithTimeout(service, 60); err != nil {
					logger.Error("Failed to stop service", "service", service, "error", err)
				}
			} else {
				if err := dockerClient.StopContainer(service); err != nil {
					logger.Error("Failed to stop service", "service", service, "error", err)
				}
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Services shutdown successfully",
		})
	}
}

// ServiceAction performs start/stop/restart action on a service
func ServiceAction(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		var req models.ServiceAction
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Performing service action", "service", req.Service, "action", req.Action)

		timeout := 30
		if req.Service == "traefik" {
			timeout = 60
		}

		containerName := req.Service
		switch req.Service {
		case "crowdsec":
			containerName = cfg.CrowdsecContainerName
		case "traefik":
			containerName = cfg.TraefikContainerName
		case "pangolin":
			if !cfg.IncludePangolin {
				c.JSON(http.StatusBadRequest, models.Response{
					Success: false,
					Error:   "Pangolin service is not enabled",
				})
				return
			}
			containerName = cfg.PangolinContainerName
		case "gerbil":
			if !cfg.IncludeGerbil {
				c.JSON(http.StatusBadRequest, models.Response{
					Success: false,
					Error:   "Gerbil service is not enabled",
				})
				return
			}
			containerName = cfg.GerbilContainerName
		}

		var err error
		switch req.Action {
		case "start":
			err = dockerClient.StartContainer(containerName)
		case "stop":
			err = dockerClient.StopContainerWithTimeout(containerName, timeout)
		case "restart":
			err = dockerClient.RestartContainerWithTimeout(containerName, timeout)
		default:
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid action. Must be start, stop, or restart",
			})
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
			Message: fmt.Sprintf("Service %s %sed successfully", req.Service, req.Action),
		})
	}
}

// CheckTraefikIntegration checks Traefik-CrowdSec integration
func CheckTraefikIntegration(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		logger.Info("Checking Traefik integration")

		integration := models.TraefikIntegration{
			MiddlewareConfigured: false,
			ConfigFiles:          []string{},
			LapiKeyFound:         false,
			AppsecEnabled:        false,
			CaptchaEnabled:       false,
			CaptchaProvider:      "",
			CaptchaHTMLExists:    false,
		}

		dynamicConfigPath := cfg.TraefikDynamicConfig
		if db != nil {
			if path, err := db.GetTraefikDynamicConfigPath(); err == nil {
				dynamicConfigPath = path
			}
		}

		var config string
		var configPaths []string

		if result, err := traefikconfig.ReadContainer(dockerClient, cfg.TraefikContainerName, dynamicConfigPath); err == nil && result.Content != "" {
			config = result.Content
			configPaths = append(configPaths, result.SourcePaths...)
		} else if output, err := dockerClient.ReadFileFromContainer(cfg.TraefikContainerName, cfg.TraefikStaticConfig); err == nil && output != "" {
			config = output
			configPaths = append(configPaths, cfg.TraefikStaticConfig)
		}

		if config == "" {
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    integration,
				Message: "No Traefik config files found",
			})
			return
		}

		integration.MiddlewareConfigured = true
		integration.ConfigFiles = append(integration.ConfigFiles, configPaths...)

		configLower := strings.ToLower(config)

		if strings.Contains(configLower, "crowdsec-bouncer-traefik-plugin") ||
			strings.Contains(configLower, "crowdseclapikey") ||
			strings.Contains(configLower, "crowdsec") {
			integration.LapiKeyFound = true
		}

		if strings.Contains(configLower, "appsec") {
			integration.AppsecEnabled = true
		}

		captchaEnabled, captchaProvider, _ := detectCaptchaInConfig(config)
		integration.CaptchaEnabled = captchaEnabled
		integration.CaptchaProvider = captchaProvider

		captchaExists, captchaErr := dockerClient.FileExists(cfg.TraefikContainerName, cfg.TraefikCaptchaHTMLPath)
		if captchaErr == nil && captchaExists {
			integration.CaptchaHTMLExists = true
		}

		logger.Info("Traefik integration check complete",
			"middleware", integration.MiddlewareConfigured,
			"lapi_key", integration.LapiKeyFound,
			"appsec", integration.AppsecEnabled)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    integration,
		})
	}
}
