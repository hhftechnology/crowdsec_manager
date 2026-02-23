package handlers

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/constants"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// GetDiscordConfig retrieves the current Discord configuration
func GetDiscordConfig(db *database.Database, cfg *config.Config, dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		settings, err := db.GetSettings()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get settings: %v", err),
			})
			return
		}

		// Check if enabled in profiles.yaml (read from host config)
		enabled := false
		profilesPath := filepath.Join(cfg.ConfigDir, constants.CrowdSecConfigSubdir, "profiles.yaml")
		if _, err := os.Stat(profilesPath); err == nil {
			enabled, _ = isDiscordEnabled(profilesPath)
		}

		// Start with database values
		config := models.DiscordConfig{
			Enabled:        enabled,
			WebhookID:      settings.DiscordWebhookID,
			WebhookToken:   settings.DiscordWebhookToken,
			GeoapifyKey:    settings.GeoapifyKey,
			CrowdSecCTIKey: settings.CrowdSecCTIKey,
			ConfigSource:   "database",
		}

		// Try to read from container to detect manual configuration
		containerConfig, err := readDiscordConfigFromContainer(dockerClient, cfg)
		if err == nil && containerConfig != nil {
			if containerConfig.ManuallyConfigured {
				config.ManuallyConfigured = true
				config.ConfigSource = "container"

				if config.WebhookID == "" && containerConfig.WebhookID != "" {
					config.WebhookID = containerConfig.WebhookID
					logger.Info("Pre-populated WebhookID from manually configured container discord.yaml")
				}
				if config.WebhookToken == "" && containerConfig.WebhookToken != "" {
					config.WebhookToken = containerConfig.WebhookToken
					logger.Info("Pre-populated WebhookToken from manually configured container discord.yaml")
				}
				if config.GeoapifyKey == "" && containerConfig.GeoapifyKey != "" {
					config.GeoapifyKey = containerConfig.GeoapifyKey
					logger.Info("Pre-populated GeoapifyKey from manually configured container discord.yaml")
				}

				if settings.DiscordWebhookID != "" || settings.DiscordWebhookToken != "" {
					config.ConfigSource = "both"
				}
			} else {
				config.ConfigSource = "database"
			}
		} else {
			if config.WebhookID == "" && config.WebhookToken == "" {
				config.ConfigSource = "none"
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    config,
		})
	}
}

// UpdateDiscordConfig updates the Discord configuration
func UpdateDiscordConfig(db *database.Database, cfg *config.Config, dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		var req models.DiscordConfig
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		// Update database
		settings, err := db.GetSettings()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get settings: %v", err),
			})
			return
		}

		settings.DiscordWebhookID = req.WebhookID
		settings.DiscordWebhookToken = req.WebhookToken
		settings.GeoapifyKey = req.GeoapifyKey
		settings.CrowdSecCTIKey = req.CrowdSecCTIKey

		if err := db.UpdateSettings(settings); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update settings: %v", err),
			})
			return
		}

		// 1. Generate discord.yaml directly in CrowdSec container config
		if err := generateDiscordYamlInContainer(dockerClient, cfg, req); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to generate discord.yaml: %v", err),
			})
			return
		}

		// 2. Update docker-compose.yml with environment variables ONLY (no volume mount)
		composeFiles := []string{
			"docker-compose.yml",
			"docker-compose.pangolin.yml",
			"docker-compose.dev.yml",
		}
		var composeErr error
		for _, composeFile := range composeFiles {
			composePath := filepath.Join(cfg.ConfigDir, "..", composeFile)
			if _, err := os.Stat(composePath); err == nil {
				logger.Info("Updating docker-compose file", "file", composeFile)
				if err := updateDockerComposeEnvOnly(composePath, req); err != nil {
					logger.Warn("Failed to update docker-compose", "file", composeFile, "error", err)
					composeErr = err
				} else {
					logger.Info("Successfully updated docker-compose", "file", composeFile)
					break
				}
			}
		}

		if composeErr != nil {
			logger.Warn("Could not update any docker-compose file", "error", composeErr)
		}

		// 3. Update config.yaml for CTI API if CTI key is provided
		if req.CrowdSecCTIKey != "" {
			configPath := filepath.Join(cfg.ConfigDir, constants.CrowdSecConfigSubdir, "config.yaml")
			if err := updateCrowdSecConfig(configPath, true); err != nil {
				logger.Warn("Failed to update config.yaml for CTI", "error", err)
			}
		}

		// 4. Update profiles.yaml
		profilesPath := filepath.Join(cfg.ConfigDir, constants.CrowdSecConfigSubdir, "profiles.yaml")
		if err := updateProfilesYaml(profilesPath, req.Enabled); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update profiles.yaml: %v", err),
			})
			return
		}

		// 5. Restart CrowdSec if requested
		restarted := false
		if req.CrowdSecRestarted {
			if err := dockerClient.RestartContainerWithTimeout(cfg.CrowdsecContainerName, 30); err != nil {
				logger.Error("Failed to restart CrowdSec", "error", err)
			} else {
				restarted = true
			}
		}

		req.CrowdSecRestarted = restarted

		// Build success message
		message := "Discord configuration updated successfully. "
		if req.Enabled {
			message += "Created discord.yaml in CrowdSec config and updated docker-compose.yml with environment variables. "
			if restarted {
				message += "CrowdSec container restarted. Run 'docker-compose up -d' to apply environment variable changes."
			} else {
				message += "Run 'docker-compose up -d' to apply environment variable changes."
			}
		} else {
			message += "Discord notifications disabled in profiles.yaml."
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: message,
			Data:    req,
		})
	}
}
