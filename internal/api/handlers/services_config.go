package handlers

import (
	"fmt"
	"net/http"

	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// GetSettings retrieves application settings from the database
func GetSettings(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		settings, err := db.GetSettings()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, models.Response{Success: true, Data: settings})
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
		dockerClient = resolveDockerClient(c, dockerClient)
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
