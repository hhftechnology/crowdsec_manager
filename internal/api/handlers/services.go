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

	"github.com/gin-gonic/gin"
)

// =============================================================================
// SERVICES
// =============================================================================

// VerifyServices verifies all services are running
func VerifyServices(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
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
		logger.Info("Performing graceful shutdown")

		// Shutdown in reverse order of startup (roughly)
		// Current list: Traefik, Pangolin, Gerbil, Crowdsec
		// Shutdown: Crowdsec, Gerbil, Pangolin, Traefik
		services := make([]string, len(cfg.ServicesWithCrowdsec))
		copy(services, cfg.ServicesWithCrowdsec)
		
		// Reverse the slice for shutdown
		for i, j := 0, len(services)-1; i < j; i, j = i+1, j-1 {
			services[i], services[j] = services[j], services[i]
		}

		for _, service := range services {
			logger.Info("Stopping service", "service", service)
			// Use longer timeout for Traefik
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
		var req models.ServiceAction
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Performing service action", "service", req.Service, "action", req.Action)

		// Use longer timeout for Traefik to allow graceful shutdown
		timeout := 30
		if req.Service == "traefik" {
			timeout = 60
		}

		// Map service names to container names
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

		var config string
		var configPath string

		// Try each path until we find one that works
		for _, path := range configPaths {
			output, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{"cat", path})
			if err == nil && output != "" {
				config = output
				configPath = path
				break
			}
		}

		if config == "" {
			// No config found, return empty integration
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    integration,
				Message: "No Traefik config files found",
			})
			return
		}

		// Config found - proceed with checks
		integration.MiddlewareConfigured = true
		integration.ConfigFiles = append(integration.ConfigFiles, configPath)

		// Better detection logic - use case-insensitive matching
		configLower := strings.ToLower(config)

		// Check for CrowdSec bouncer plugin
		if strings.Contains(configLower, "crowdsec-bouncer-traefik-plugin") ||
			strings.Contains(configLower, "crowdseclapikey") ||
			strings.Contains(configLower, "crowdsec") {
			integration.LapiKeyFound = true
		}

		// Check for AppSec
		if strings.Contains(configLower, "appsec") {
			integration.AppsecEnabled = true
		}

		// Check for Captcha
		captchaEnabled, captchaProvider, _ := detectCaptchaInConfig(config)
		integration.CaptchaEnabled = captchaEnabled
		integration.CaptchaProvider = captchaProvider

		// Check if captcha.html exists in Traefik container
		captchaExists, captchaErr := dockerClient.FileExists(cfg.TraefikContainerName, "/etc/traefik/conf/captcha.html")
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

// GetTraefikConfig retrieves Traefik configuration
func GetTraefikConfig() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting Traefik config")

		// In a real implementation, read from config file
		config := gin.H{
			"static":  "traefik_config.yml content",
			"dynamic": "dynamic_config.yml content",
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    config,
		})
	}
}

// GetTraefikConfigPath retrieves the current dynamic config path
func GetTraefikConfigPath(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting Traefik config path")

		settings, err := db.GetSettings()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get settings: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: gin.H{
				"dynamic_config_path": settings.TraefikDynamicConfig,
				"static_config_path":  settings.TraefikStaticConfig,
				"access_log_path":     settings.TraefikAccessLog,
				"error_log_path":      settings.TraefikErrorLog,
				"crowdsec_acquis":     settings.CrowdSecAcquisFile,
			},
		})
	}
}

// SetTraefikConfigPath sets the dynamic config path
func SetTraefikConfigPath(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.ConfigPathRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Setting Traefik config path", "path", req.DynamicConfigPath)

		// Update database
		err := db.SetTraefikDynamicConfigPath(req.DynamicConfigPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update config path: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Dynamic config path updated successfully",
			Data:    gin.H{"dynamic_config_path": req.DynamicConfigPath},
		})
	}
}

// UpdateSettings updates all file path settings
func UpdateSettings(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req database.Settings
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Updating settings")

		err := db.UpdateSettings(&req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update settings: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Settings updated successfully",
			Data:    req,
		})
	}
}

// GetFileContent reads a file from a Docker container
func GetFileContent(dockerClient *docker.Client, db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		container := c.Param("container")
		fileType := c.Param("fileType")

		logger.Info("Getting file content", "container", container, "fileType", fileType)

		settings, _ := db.GetSettings()

		var filePath string
		switch fileType {
		case "dynamic_config":
			filePath = settings.TraefikDynamicConfig
		case "static_config":
			filePath = settings.TraefikStaticConfig
		case "access_log":
			filePath = settings.TraefikAccessLog
		case "error_log":
			filePath = settings.TraefikErrorLog
		case "crowdsec_acquis":
			filePath = settings.CrowdSecAcquisFile
		default:
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid file type",
			})
			return
		}

		content, err := dockerClient.ExecCommand(container, []string{"cat", filePath})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to read file: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: gin.H{
				"path":    filePath,
				"content": content,
			},
		})
	}
}
