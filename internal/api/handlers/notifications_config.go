package handlers

import (
	"encoding/json"
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

// SaveDiscordConfig persists Discord notification configuration to the database without applying it.
// This decouples the save step from the apply step so the user can review before committing.
func SaveDiscordConfig(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.DiscordConfig
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		if req.WebhookID == "" || req.WebhookToken == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "webhook_id and webhook_token are required",
			})
			return
		}

		configJSON, err := json.Marshal(req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to serialize config: " + err.Error(),
			})
			return
		}

		if err := db.SaveFeatureConfig("discord_notifications", string(configJSON), "user"); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to save config to database: " + err.Error(),
			})
			return
		}

		logger.Info("Discord notification config saved to database")

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Discord notification configuration saved. Use POST /api/notifications/discord/apply to apply it.",
			Data: gin.H{
				"saved": true,
				"next_steps": []string{
					"Review the configuration",
					"Click Apply to write config files and optionally restart CrowdSec",
				},
			},
		})
	}
}

// ApplyDiscordConfig reads the Discord config saved by SaveDiscordConfig and applies it to all
// systems: legacy settings DB, discord.yaml in the container, docker-compose env vars,
// profiles.yaml, and an optional CrowdSec restart.
func ApplyDiscordConfig(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		// Load config from feature_configs table.
		featureCfg, err := db.GetFeatureConfig("discord_notifications")
		if err != nil || featureCfg == nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "No Discord notification config found. Save config first via POST /api/notifications/discord/config",
			})
			return
		}

		var discordCfg models.DiscordConfig
		if err := json.Unmarshal([]byte(featureCfg.ConfigJSON), &discordCfg); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to parse saved config: " + err.Error(),
			})
			return
		}

		steps := []gin.H{}

		// Step 1: Persist credentials to the legacy settings table for backward compatibility.
		settings, _ := db.GetSettings()
		if settings == nil {
			settings = &database.Settings{ID: 1}
		}
		settings.DiscordWebhookID = discordCfg.WebhookID
		settings.DiscordWebhookToken = discordCfg.WebhookToken
		settings.GeoapifyKey = discordCfg.GeoapifyKey
		settings.CrowdSecCTIKey = discordCfg.CrowdSecCTIKey
		dbErr := db.UpdateSettings(settings)
		steps = append(steps, gin.H{
			"step":    1,
			"name":    "Save credentials to database",
			"success": dbErr == nil,
			"error":   errString(dbErr),
		})

		// Step 2: Write discord.yaml directly into the CrowdSec container.
		yamlErr := generateDiscordYamlInContainer(dockerClient, cfg, discordCfg)
		steps = append(steps, gin.H{
			"step":    2,
			"name":    "Generate discord.yaml in CrowdSec container",
			"success": yamlErr == nil,
			"error":   errString(yamlErr),
		})

		// Step 3: Update docker-compose env vars for each compose file that exists.
		composeFiles := []string{
			"docker-compose.yml",
			"docker-compose.pangolin.yml",
			"docker-compose.dev.yml",
		}
		var composeErr error
		for _, composeFile := range composeFiles {
			composePath := filepath.Join(cfg.ConfigDir, "..", composeFile)
			if _, statErr := os.Stat(composePath); statErr == nil {
				if err := updateDockerComposeEnvOnly(composePath, discordCfg); err != nil {
					logger.Warn("Failed to update docker-compose", "file", composeFile, "error", err)
					composeErr = err
				} else {
					logger.Info("Updated docker-compose env vars", "file", composeFile)
					composeErr = nil
					break
				}
			}
		}
		steps = append(steps, gin.H{
			"step":    3,
			"name":    "Update docker-compose.yml environment variables",
			"success": composeErr == nil,
			"error":   errString(composeErr),
		})

		// Step 4: Update profiles.yaml to enable/disable the discord notification.
		profilesPath := filepath.Join(cfg.ConfigDir, constants.CrowdSecConfigSubdir, "profiles.yaml")
		profilesErr := updateProfilesYaml(profilesPath, discordCfg.Enabled)
		steps = append(steps, gin.H{
			"step":    4,
			"name":    "Update CrowdSec profiles.yaml",
			"success": profilesErr == nil,
			"error":   errString(profilesErr),
		})

		// Step 5: Optionally restart CrowdSec when the caller requests it.
		var restartErr error
		skipped := !discordCfg.CrowdSecRestarted
		if !skipped {
			restartErr = restartCrowdSecContainer(dockerClient, cfg)
		}
		steps = append(steps, gin.H{
			"step":    5,
			"name":    "Restart CrowdSec",
			"success": restartErr == nil,
			"error":   errString(restartErr),
			"skipped": skipped,
		})

		// All critical steps: DB save, YAML generation, profiles update.
		allCriticalOK := dbErr == nil && yamlErr == nil && profilesErr == nil
		if allCriticalOK {
			if markErr := db.MarkFeatureApplied("discord_notifications"); markErr != nil {
				logger.Warn("Failed to mark discord_notifications as applied in DB", "error", markErr)
			}
		}

		message := "Discord notifications applied successfully"
		if !allCriticalOK {
			message = "Discord notifications applied with some errors — check step details"
		}

		c.JSON(http.StatusOK, models.Response{
			Success: allCriticalOK,
			Message: message,
			Data: gin.H{
				"steps":   steps,
				"applied": allCriticalOK,
			},
		})
	}
}
