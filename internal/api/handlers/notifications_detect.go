package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"crowdsec-manager/internal/compose"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// DetectDiscordConfig scans all sources for existing Discord notification configuration
// and returns a FeatureDetectionResult without modifying anything.
func DetectDiscordConfig(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		detected := map[string]interface{}{}
		sources := map[string]bool{
			"docker_compose": false,
			"container_yaml": false,
			"profiles_yaml":  false,
			"database":       false,
		}

		// 1. Scan docker-compose files for notification-related env vars.
		notifEnvKeys := []string{
			"DISCORD_WEBHOOK_ID",
			"DISCORD_WEBHOOK_TOKEN",
			"GEOAPIFY_API_KEY",
			"CROWDSEC_CTI_API_KEY",
		}
		composeFiles := findComposeFiles(cfg)
		composeResult, err := compose.ScanMultipleComposeFiles(composeFiles, nil, notifEnvKeys)
		if err == nil && composeResult.Found {
			sources["docker_compose"] = true
			for k, v := range composeResult.Values {
				detected[strings.ToLower(k)] = v
			}
		}

		// 2. Check for discord.yaml in the CrowdSec container.
		discordYAMLPath := cfg.CrowdSecNotificationsDir + "/discord.yaml"
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cat", discordYAMLPath})
		if err == nil && strings.TrimSpace(output) != "" {
			sources["container_yaml"] = true
			detected["discord_yaml_exists"] = true
			// Detect whether it uses env-var templates or hardcoded values.
			if strings.Contains(output, "${DISCORD_WEBHOOK_ID}") {
				detected["discord_yaml_type"] = "template"
			} else {
				detected["discord_yaml_type"] = "manual"
			}
		} else {
			detected["discord_yaml_exists"] = false
		}

		// 3. Check profiles.yaml for a discord notification reference.
		profileOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cat", cfg.CrowdSecProfilesPath})
		if err == nil {
			if strings.Contains(profileOutput, "discord") {
				sources["profiles_yaml"] = true
				detected["profiles_enabled"] = true
			} else {
				detected["profiles_enabled"] = false
			}
		}

		// 4. Check DB feature_configs table for a saved Discord config.
		var dbConfig *models.FeatureConfig
		if db != nil {
			dbConfig, _ = db.GetFeatureConfig("discord_notifications")
			if dbConfig != nil {
				sources["database"] = true
				var stored map[string]interface{}
				if json.Unmarshal([]byte(dbConfig.ConfigJSON), &stored) == nil {
					for k, v := range stored {
						if _, exists := detected[k]; !exists {
							detected[k] = v
						}
					}
				}
			}

			// 5. Also check the legacy settings table for backwards compatibility.
			settings, settingsErr := db.GetSettings()
			if settingsErr == nil && settings != nil {
				if settings.DiscordWebhookID != "" {
					if _, exists := detected["discord_webhook_id"]; !exists {
						detected["discord_webhook_id"] = settings.DiscordWebhookID
					}
					sources["database"] = true
				}
				if settings.DiscordWebhookToken != "" {
					if _, exists := detected["discord_webhook_token"]; !exists {
						detected["discord_webhook_token"] = settings.DiscordWebhookToken
					}
				}
				if settings.GeoapifyKey != "" {
					if _, exists := detected["geoapify_api_key"]; !exists {
						detected["geoapify_api_key"] = settings.GeoapifyKey
					}
				}
				if settings.CrowdSecCTIKey != "" {
					if _, exists := detected["crowdsec_cti_api_key"]; !exists {
						detected["crowdsec_cti_api_key"] = settings.CrowdSecCTIKey
					}
				}
			}
		}

		// Determine overall status.
		status := "not_configured"
		switch {
		case sources["database"] && dbConfig != nil && dbConfig.Applied:
			status = "applied"
		case sources["container_yaml"] && sources["profiles_yaml"]:
			status = "configured"
		case sources["docker_compose"] || sources["database"] || sources["container_yaml"]:
			status = "partially_configured"
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: models.FeatureDetectionResult{
				DetectedValues: detected,
				Sources:        sources,
				DBConfig:       dbConfig,
				Status:         status,
			},
		})
	}
}
