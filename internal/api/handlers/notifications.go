package handlers

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-yaml"
)

// DiscordTemplate is the template for discord.yaml
const DiscordTemplate = `
type: http
name: discord
log_level: info
format: |
  {
    "embeds": [
      {
        {{range . -}}
        {{$alert := . -}}
        {{range .Decisions -}}
        {{- $cti := .Value | CrowdsecCTI  -}}
        "timestamp": "{{$alert.StartAt}}",
        "title": "Crowdsec Alert",
        "color": 16711680,
        "description": "Potential threat detected. View details in [Crowdsec Console](<https://app.crowdsec.net/cti/{{.Value}}>)",
        "url": "https://app.crowdsec.net/cti/{{.Value}}",
        {{if $alert.Source.Cn -}}
        "image": {
          "url": "https://maps.geoapify.com/v1/staticmap?style=osm-bright-grey&width=600&height=400&center=lonlat:{{$alert.Source.Longitude}},{{$alert.Source.Latitude}}&zoom=8.1848&marker=lonlat:{{$alert.Source.Longitude}},{{$alert.Source.Latitude}};type:awesome;color:%23655e90;size:large;icon:industry|lonlat:{{$alert.Source.Longitude}},{{$alert.Source.Latitude}};type:material;color:%23ff3421;icontype:awesome&scaleFactor=2&apiKey={{env "GEOAPIFY_API_KEY"}}"
        },
        {{end}}
        "fields": [
              {
                "name": "Scenario",
                "value": "` + "`{{ .Scenario }}`" + `",
                "inline": "true"
              },
              {
                "name": "IP",
                "value": "[{{.Value}}](<https://www.whois.com/whois/{{.Value}}>)",
                "inline": "true"
              },
              {
                "name": "Ban Duration",
                "value": "{{.Duration}}",
                "inline": "true"
              },
              {{if $alert.Source.Cn -}}
              { 
                "name": "Country",
                "value": "{{$alert.Source.Cn}} :flag_{{ $alert.Source.Cn | lower }}:",
                "inline": "true"
              }
              {{if $cti.Location.City -}}
              ,
              { 
                "name": "City",
                "value": "{{$cti.Location.City}}",
                "inline": "true"
              },
              { 
                "name": "Maliciousness",
                "value": "{{mulf $cti.GetMaliciousnessScore 100 | floor}} %",
                "inline": "true"
              }
              {{end}}
              {{end}}
              {{if not $alert.Source.Cn -}}
              { 
                "name": "Location",
                "value": "Unknown :pirate_flag:"
              }
              {{end}}
              {{end -}}
              {{end -}}
              {{range . -}}
              {{$alert := . -}}
              {{range .Meta -}}
                ,{
                "name": "{{.Key}}",
                "value": "{{ (splitList "," (.Value | replace "\"" "` + "`" + `" | replace "[" "" |replace "]" "")) | join "\\n"}}"
              } 
              {{end -}}
              {{end -}}
        ]
      }
    ]
  }
url: https://discord.com/api/webhooks/${DISCORD_WEBHOOK_ID}/${DISCORD_WEBHOOK_TOKEN}
method: POST
headers:
  Content-Type: application/json
`

// parseDiscordYaml reads discord.yaml and extracts webhook config
func parseDiscordYaml(path string) (*models.DiscordConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var yamlData map[string]interface{}
	if err := yaml.Unmarshal(data, &yamlData); err != nil {
		return nil, err
	}

	config := &models.DiscordConfig{}

	// Extract URL: https://discord.com/api/webhooks/{ID}/{TOKEN}
	if urlStr, ok := yamlData["url"].(string); ok {
		// Parse webhook ID and token from URL
		if strings.Contains(urlStr, "discord.com/api/webhooks/") {
			parts := strings.Split(urlStr, "/")
			if len(parts) >= 7 {
				config.WebhookID = parts[5]
				config.WebhookToken = parts[6]
			}
		}
	}

	// Extract format string to get Geoapify key (check if it's hardcoded in the template)
	if formatStr, ok := yamlData["format"].(string); ok {
		// Look for actual API key value (not template variable)
		if strings.Contains(formatStr, "geoapify") {
			re := regexp.MustCompile(`apiKey=([A-Za-z0-9]+)`)
			matches := re.FindStringSubmatch(formatStr)
			if len(matches) > 1 {
				config.GeoapifyKey = matches[1]
			}
		}
	}

	return config, nil
}

// GetDiscordConfig retrieves the current Discord configuration
func GetDiscordConfig(db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
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
		profilesPath := filepath.Join(cfg.ConfigDir, "crowdsec", "profiles.yaml")
		if _, err := os.Stat(profilesPath); err == nil {
			enabled, _ = isDiscordEnabled(profilesPath)
		}

		// Start with database values
		config := models.DiscordConfig{
			Enabled:      enabled,
			WebhookID:    settings.DiscordWebhookID,
			WebhookToken: settings.DiscordWebhookToken,
			GeoapifyKey:  settings.GeoapifyKey,
			CTIKey:       settings.CTIKey,
		}

		// Note: We don't read from container's discord.yaml because it uses environment variable syntax
		// The database is the source of truth for the actual values
		// The container file just references ${DISCORD_WEBHOOK_ID} etc.

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    config,
		})
	}
}

// UpdateDiscordConfig updates the Discord configuration
func UpdateDiscordConfig(db *database.Database, cfg *config.Config, dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
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
		settings.CTIKey = req.CTIKey

		if err := db.UpdateSettings(settings); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update settings: %v", err),
			})
			return
		}

		// 1. Generate discord.yaml directly in CrowdSec container config
		// Write to the existing crowdsec-config volume, not a separate mount
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
					break // Success, no need to try other files
				}
			}
		}

		if composeErr != nil {
			logger.Warn("Could not update any docker-compose file", "error", composeErr)
		}

		// 3. Update config.yaml for CTI API if CTI key is provided
		if req.CTIKey != "" {
			configPath := filepath.Join(cfg.ConfigDir, "crowdsec", "config.yaml")
			if err := updateCrowdSecConfig(configPath, true); err != nil {
				logger.Warn("Failed to update config.yaml for CTI", "error", err)
				// Don't fail the request, CTI is optional
			}
		}

		// 4. Update profiles.yaml
		profilesPath := filepath.Join(cfg.ConfigDir, "crowdsec", "profiles.yaml")
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
				// Don't fail the request, just note it
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

// Helper functions

func isDiscordEnabled(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	var profiles map[string]interface{}
	if err := yaml.Unmarshal(data, &profiles); err != nil {
		return false, err
	}

	// This is a simplified check. Real profiles.yaml structure is complex.
	// We assume a standard structure where we look for 'notifications' list in the first profile or all profiles.
	// But yaml.Unmarshal into map[string]interface{} might be too generic.
	// Let's try to find "discord" in the file content as a simple heuristic first, 
	// or better, parse it properly.
	
	// Since we are modifying it, we should parse it properly.
	// However, the structure of profiles.yaml can vary.
	// Let's define a minimal struct for what we need.
	
	// Re-reading file for proper parsing
	return strings.Contains(string(data), "- discord"), nil
}

func updateProfilesYaml(path string, enable bool) error {
	// Reading the file
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	content := string(data)
	hasDiscord := strings.Contains(content, "- discord")

	if enable && !hasDiscord {
		// Add discord to notifications
		// We look for "notifications:" and add "- discord" under it.
		// This is a bit brittle with string replacement but safer than re-marshalling which might lose comments/formatting.
		if strings.Contains(content, "notifications:") {
			lines := strings.Split(content, "\n")
			var newLines []string
			for _, line := range lines {
				newLines = append(newLines, line)
				if strings.TrimSpace(line) == "notifications:" {
					// Check indentation
					indent := ""
					for _, char := range line {
						if char == ' ' || char == '\t' {
							indent += string(char)
						} else {
							break
						}
					}
					newLines = append(newLines, indent+"  - discord")
				}
			}
			return os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0644)
		} else {
			// If no notifications section, append it to the end
			newContent := content
			if !strings.HasSuffix(newContent, "\n") {
				newContent += "\n"
			}
			newContent += "notifications:\n  - discord\n"
			return os.WriteFile(path, []byte(newContent), 0644)
		}
	} else if !enable && hasDiscord {
		// Remove discord
		lines := strings.Split(content, "\n")
		var newLines []string
		for _, line := range lines {
			if strings.Contains(line, "- discord") {
				continue
			}
			newLines = append(newLines, line)
		}
		return os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0644)
	}

	return nil
}

// generateDiscordYamlInContainer writes discord.yaml directly to CrowdSec container config
func generateDiscordYamlInContainer(dockerClient *docker.Client, cfg *config.Config, config models.DiscordConfig) error {
	// Create notifications directory if it doesn't exist
	_, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"mkdir", "-p", "/etc/crowdsec/notifications",
	})
	if err != nil {
		logger.Warn("Failed to create notifications directory (may already exist)", "error", err)
	}

	// Escape single quotes in the template for shell command
	escapedTemplate := strings.ReplaceAll(DiscordTemplate, "'", "'\\''")

	// Write discord.yaml directly to container
	_, err = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"sh", "-c", fmt.Sprintf("echo '%s' > /etc/crowdsec/notifications/discord.yaml", escapedTemplate),
	})
	if err != nil {
		return fmt.Errorf("failed to write discord.yaml to container: %w", err)
	}

	logger.Info("Discord YAML created in CrowdSec container", "path", "/etc/crowdsec/notifications/discord.yaml")
	return nil
}

// updateDockerComposeEnvOnly updates docker-compose.yml to add Discord environment variables ONLY (no volume mount)
func updateDockerComposeEnvOnly(composePath string, config models.DiscordConfig) error {
	// Read docker-compose.yml
	data, err := os.ReadFile(composePath)
	if err != nil {
		return fmt.Errorf("failed to read docker-compose.yml: %w", err)
	}

	// Parse YAML
	var compose map[string]interface{}
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return fmt.Errorf("failed to parse docker-compose.yml: %w", err)
	}

	// Navigate to services -> crowdsec
	services, ok := compose["services"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("services section not found in docker-compose.yml")
	}

	crowdsec, ok := services["crowdsec"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("crowdsec service not found in docker-compose.yml")
	}

	// Update environment variables
	env, ok := crowdsec["environment"]
	if !ok {
		// Create environment map if it doesn't exist
		crowdsec["environment"] = make(map[string]interface{})
		env = crowdsec["environment"]
	}

	envMap, ok := env.(map[string]interface{})
	if !ok {
		return fmt.Errorf("environment section has unexpected format")
	}

	// Add/update environment variables with actual values
	envMap["GEOAPIFY_API_KEY"] = config.GeoapifyKey
	envMap["DISCORD_WEBHOOK_ID"] = config.WebhookID
	envMap["DISCORD_WEBHOOK_TOKEN"] = config.WebhookToken
	if config.CTIKey != "" {
		envMap["CTI_API_KEY"] = config.CTIKey
	}

	// DO NOT add volume mount - discord.yaml is written directly to crowdsec-config volume

	// Write back to file
	updatedData, err := yaml.Marshal(compose)
	if err != nil {
		return fmt.Errorf("failed to marshal docker-compose.yml: %w", err)
	}

	if err := os.WriteFile(composePath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write docker-compose.yml: %w", err)
	}

	logger.Info("Docker Compose updated with environment variables (no volume mount added)")
	return nil
}

// createOrUpdateEnvFile creates or updates the .env file with Discord notification variables
func createOrUpdateEnvFile(envPath string, config models.DiscordConfig) error {
	// Read existing .env file if it exists
	var envVars map[string]string
	data, err := os.ReadFile(envPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read .env file: %w", err)
	}

	// Parse existing env vars
	envVars = make(map[string]string)
	if len(data) > 0 {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				envVars[parts[0]] = parts[1]
			}
		}
	}

	// Update Discord-related variables
	envVars["GEOAPIFY_API_KEY"] = config.GeoapifyKey
	envVars["DISCORD_WEBHOOK_ID"] = config.WebhookID
	envVars["DISCORD_WEBHOOK_TOKEN"] = config.WebhookToken
	if config.CTIKey != "" {
		envVars["CTI_API_KEY"] = config.CTIKey
	}

	// Build new .env content
	var lines []string
	lines = append(lines, "# Discord Notification Configuration")
	lines = append(lines, fmt.Sprintf("GEOAPIFY_API_KEY=%s", envVars["GEOAPIFY_API_KEY"]))
	lines = append(lines, fmt.Sprintf("DISCORD_WEBHOOK_ID=%s", envVars["DISCORD_WEBHOOK_ID"]))
	lines = append(lines, fmt.Sprintf("DISCORD_WEBHOOK_TOKEN=%s", envVars["DISCORD_WEBHOOK_TOKEN"]))
	if config.CTIKey != "" {
		lines = append(lines, fmt.Sprintf("CTI_API_KEY=%s", envVars["CTI_API_KEY"]))
	}
	lines = append(lines, "")

	// Append other non-Discord variables
	for key, value := range envVars {
		if key != "GEOAPIFY_API_KEY" && key != "DISCORD_WEBHOOK_ID" &&
		   key != "DISCORD_WEBHOOK_TOKEN" && key != "CTI_API_KEY" {
			lines = append(lines, fmt.Sprintf("%s=%s", key, value))
		}
	}

	// Write back to file
	content := strings.Join(lines, "\n")
	if err := os.WriteFile(envPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write .env file: %w", err)
	}

	return nil
}

// updateCrowdSecConfig updates CrowdSec config.yaml to enable CTI API if CTI key is provided
func updateCrowdSecConfig(configPath string, enableCTI bool) error {
	if !enableCTI {
		return nil // Skip if not enabling CTI
	}

	// Read config.yaml
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config.yaml: %w", err)
	}

	// Parse YAML
	var config map[string]interface{}
	if err := yaml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config.yaml: %w", err)
	}

	// Navigate to api section
	api, ok := config["api"]
	if !ok {
		config["api"] = make(map[string]interface{})
		api = config["api"]
	}

	apiMap, ok := api.(map[string]interface{})
	if !ok {
		return fmt.Errorf("api section has unexpected format")
	}

	// Add CTI configuration
	ctiConfig := map[string]interface{}{
		"key":           "${CTI_API_KEY}",
		"cache_timeout": "60m",
		"cache_size":    50,
		"enabled":       true,
		"log_level":     "debug",
	}

	apiMap["cti"] = ctiConfig

	// Write back to file
	updatedData, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config.yaml: %w", err)
	}

	if err := os.WriteFile(configPath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write config.yaml: %w", err)
	}

	return nil
}
