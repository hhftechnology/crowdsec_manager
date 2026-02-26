package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

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
					"Click Apply to write config files and restart CrowdSec",
				},
			},
		})
	}
}

// discordApplyStep is a named step in the apply pipeline.
type discordApplyStep struct {
	Num  int
	Name string
	Run  func(discordCfg models.DiscordConfig) error
}

// ApplyDiscordConfig reads the Discord config saved by SaveDiscordConfig and applies it to all
// systems: legacy settings DB, discord.yaml in the container, docker-compose env vars,
// profiles.yaml, and a CrowdSec restart.
//
// Supports an optional "step" query parameter to re-run a single step (e.g. ?step=4).
// When step is omitted, all steps run sequentially.
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

		// Parse optional step filter.
		var onlyStep int
		if stepStr := c.Query("step"); stepStr != "" {
			parsed, parseErr := strconv.Atoi(stepStr)
			if parseErr != nil || parsed < 1 || parsed > 5 {
				c.JSON(http.StatusBadRequest, models.Response{
					Success: false,
					Error:   "Invalid step parameter. Must be 1-5.",
				})
				return
			}
			onlyStep = parsed
		}

		// Define the pipeline of steps.
		pipeline := []discordApplyStep{
			{
				Num:  1,
				Name: "Save credentials to database",
				Run: func(dc models.DiscordConfig) error {
					settings, _ := db.GetSettings()
					if settings == nil {
						settings = &database.Settings{ID: 1}
					}
					settings.DiscordWebhookID = dc.WebhookID
					settings.DiscordWebhookToken = dc.WebhookToken
					settings.GeoapifyKey = dc.GeoapifyKey
					settings.CrowdSecCTIKey = dc.CrowdSecCTIKey
					return db.UpdateSettings(settings)
				},
			},
			{
				Num:  2,
				Name: "Generate discord.yaml in CrowdSec container",
				Run: func(dc models.DiscordConfig) error {
					return generateDiscordYamlInContainer(dockerClient, cfg, dc)
				},
			},
			{
				Num:  3,
				Name: "Update docker-compose.yml environment variables",
				Run: func(dc models.DiscordConfig) error {
					composeFiles := []string{
						"docker-compose.yml",
						"docker-compose.pangolin.yml",
						"docker-compose.dev.yml",
					}
					var lastErr error
					for _, composeFile := range composeFiles {
						composePath := filepath.Join(cfg.ConfigDir, "..", composeFile)
						if _, statErr := os.Stat(composePath); statErr == nil {
							if err := updateDockerComposeEnvOnly(composePath, dc); err != nil {
								logger.Warn("Failed to update docker-compose", "file", composeFile, "error", err)
								lastErr = err
							} else {
								logger.Info("Updated docker-compose env vars", "file", composeFile)
								return nil
							}
						}
					}
					return lastErr
				},
			},
			{
				Num:  4,
				Name: "Update CrowdSec profiles.yaml",
				Run: func(dc models.DiscordConfig) error {
					profilesPath := filepath.Join(cfg.ConfigDir, constants.CrowdSecConfigSubdir, "profiles.yaml")
					if mkdirErr := os.MkdirAll(filepath.Dir(profilesPath), 0755); mkdirErr != nil {
						logger.Warn("Failed to ensure profiles directory exists", "path", filepath.Dir(profilesPath), "error", mkdirErr)
					}
					if err := updateProfilesYaml(profilesPath, dc.Enabled); err != nil {
						logger.Error("Failed to update profiles.yaml", "path", profilesPath, "enabled", dc.Enabled, "error", err)
						return err
					}
					logger.Info("Updated profiles.yaml", "path", profilesPath, "enabled", dc.Enabled)
					return nil
				},
			},
			{
				Num:  5,
				Name: "Restart CrowdSec",
				Run: func(_ models.DiscordConfig) error {
					if err := restartCrowdSecContainer(dockerClient, cfg); err != nil {
						logger.Error("Failed to restart CrowdSec during apply", "error", err)
						return err
					}
					logger.Info("CrowdSec restarted successfully after apply")
					return nil
				},
			},
		}

		// Execute steps.
		steps := []gin.H{}
		allOK := true

		for _, s := range pipeline {
			if onlyStep > 0 && s.Num != onlyStep {
				continue
			}

			stepErr := s.Run(discordCfg)
			success := stepErr == nil
			if !success {
				allOK = false
			}

			steps = append(steps, gin.H{
				"step":    s.Num,
				"name":    s.Name,
				"success": success,
				"error":   errString(stepErr),
			})
		}

		// Mark feature as applied when all critical steps (1,2,4) succeed in a full run.
		if onlyStep == 0 && allOK {
			if markErr := db.MarkFeatureApplied("discord_notifications"); markErr != nil {
				logger.Warn("Failed to mark discord_notifications as applied in DB", "error", markErr)
			}
		}

		message := "Discord notifications applied successfully"
		if !allOK {
			message = "Discord notifications applied with some errors — check step details"
		}
		if onlyStep > 0 {
			if allOK {
				message = "Step re-run succeeded"
			} else {
				message = "Step re-run failed — check details"
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: allOK,
			Message: message,
			Data: gin.H{
				"steps":   steps,
				"applied": allOK,
			},
		})
	}
}
