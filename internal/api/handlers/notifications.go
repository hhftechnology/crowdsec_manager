package handlers

import (
	"bytes"
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
	"gopkg.in/yaml.v3"
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
        "title": "🚨 CrowdSec Security Alert",
        "color": 16711680,
        "description": "Potential threat detected. View details in [CrowdSec Console](<https://app.crowdsec.net/cti/{{.Value}}>)",
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
                "inline": false
              },
              {
                "name": "Source IP",
                "value": "[{{.Value}}](<https://www.whois.com/whois/{{.Value}}>)",
                "inline": false
              },
              {
                "name": "Ban Duration",
                "value": "{{.Duration}}",
                "inline": false
              },
              {{if $alert.Source.Cn -}}
              {
                "name": "Country",
                "value": "**{{$alert.Source.Cn}}** :flag_{{ $alert.Source.Cn | lower }}:",
                "inline": false
              }
              {{if $cti.Location.City -}}
              ,{
                "name": "City",
                "value": "**{{$cti.Location.City}}**",
                "inline": false
              },
              {
                "name": "Maliciousness",
                "value": "{{mulf $cti.GetMaliciousnessScore 100 | floor}} %",
                "inline": false
              }
              {{end}}
              {{end}}
              {{if not $alert.Source.Cn -}}
              ,{
                "name": "Location",
                "value": "Unknown :pirate_flag:",
                "inline": false
              }
              {{end}}
              {{end -}}
              {{end -}}
              {{range . -}}
              {{$alert := . -}}
              {{if GetMeta $alert "target_host" -}}
              ,{
                "name": "🎯 Target Host",
                "value": "` + "`{{GetMeta $alert \"target_host\"}}`" + `",
                "inline": false
              }
              {{end}}
              {{if GetMeta $alert "target_uri" -}}
              ,{
                "name": "🔗 Target URI",
                "value": "` + "`{{GetMeta $alert \"target_uri\"}}`" + `",
                "inline": false
              }
              {{end}}
              {{if GetMeta $alert "target_fqdn" -}}
              ,{
                "name": "🌐 Target URL",
                "value": "{{range (GetMeta $alert "target_fqdn" | uniq) -}}` + "`{{.}}`" + `\n{{ end -}}",
                "inline": false
              }
              {{end}}
              {{range .Meta -}}
                {{if and (ne .Key "target_host") (ne .Key "target_uri") (ne .Key "target_fqdn") -}}
                ,{
                  "name": "{{.Key}}",
                  "value": "{{ (splitList "," (.Value | replace "\"" "` + "`" + `" | replace "[" "" |replace "]" "")) | join "\\n"}}",
                  "inline": false
                }
                {{end -}}
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

// updateProfilesYaml updates profiles.yaml to enable/disable discord notifications
func updateProfilesYaml(path string, enable bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && enable {
			// Create new file if it doesn't exist and we are enabling
			data = []byte("")
		} else {
			return err
		}
	}

	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		// If empty or invalid, start fresh
		node = yaml.Node{
			Kind: yaml.DocumentNode,
			Content: []*yaml.Node{
				{Kind: yaml.SequenceNode},
			},
		}
	}

	if len(node.Content) == 0 {
		node.Kind = yaml.DocumentNode
		node.Content = []*yaml.Node{
			{Kind: yaml.SequenceNode},
		}
	} else if node.Content[0].Kind != yaml.SequenceNode {
		// If root is not a sequence, it might be a map (single profile?) or invalid.
		// CrowdSec profiles.yaml is a list.
		// If it's a map, we wrap it in a sequence? Or error?
		// Let's assume it's a sequence as per spec.
		return fmt.Errorf("profiles.yaml root is not a sequence")
	}
	rootSeq := node.Content[0]

	// Target profile name
	targetProfile := "default_ip_remediation"
	var profileNode *yaml.Node

	// Helper to find key in mapping
	findKey := func(parent *yaml.Node, key string) (*yaml.Node, int) {
		for i := 0; i < len(parent.Content); i += 2 {
			if parent.Content[i].Value == key {
				return parent.Content[i+1], i + 1
			}
		}
		return nil, -1
	}

	// Find the target profile
	for _, profile := range rootSeq.Content {
		if profile.Kind == yaml.MappingNode {
			nameNode, _ := findKey(profile, "name")
			if nameNode != nil && nameNode.Value == targetProfile {
				profileNode = profile
				break
			}
		}
	}

	if enable {
		if profileNode == nil {
			// Create new profile if not found
			logger.Info("Creating new profile in profiles.yaml", "profile", targetProfile)
			
			// Construct the new profile node
			// name: default_ip_remediation
			// filters:
			//  - Alert.Remediation == true && Alert.GetScope() == "Ip"
			// decisions:
			//  - type: ban
			//    duration: 4h
			// on_success: break
			// notifications:
			//  - discord

			newProfile := &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "name"},
					{Kind: yaml.ScalarNode, Value: targetProfile},
					
					{Kind: yaml.ScalarNode, Value: "filters"},
					{Kind: yaml.SequenceNode, Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Value: "Alert.Remediation == true && Alert.GetScope() == \"Ip\""},
					}},
					
					{Kind: yaml.ScalarNode, Value: "decisions"},
					{Kind: yaml.SequenceNode, Content: []*yaml.Node{
						{Kind: yaml.MappingNode, Content: []*yaml.Node{
							{Kind: yaml.ScalarNode, Value: "type"},
							{Kind: yaml.ScalarNode, Value: "ban"},
							{Kind: yaml.ScalarNode, Value: "duration"},
							{Kind: yaml.ScalarNode, Value: "4h"},
						}},
					}},
					
					{Kind: yaml.ScalarNode, Value: "on_success"},
					{Kind: yaml.ScalarNode, Value: "break"},
					
					{Kind: yaml.ScalarNode, Value: "notifications"},
					{Kind: yaml.SequenceNode, Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Value: "discord"},
					}},
				},
			}
			
			rootSeq.Content = append(rootSeq.Content, newProfile)
		} else {
			// Profile exists, check for notifications
			notificationsNode, _ := findKey(profileNode, "notifications")
			if notificationsNode == nil {
				// Add notifications section
				keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "notifications"}
				notificationsNode = &yaml.Node{Kind: yaml.SequenceNode}
				profileNode.Content = append(profileNode.Content, keyNode, notificationsNode)
			} else if notificationsNode.Kind != yaml.SequenceNode {
				// If it exists but is not a sequence (e.g. null or scalar), make it a sequence
				// This handles cases where it might be empty or malformed
				notificationsNode.Kind = yaml.SequenceNode
				notificationsNode.Content = []*yaml.Node{}
			}

			// Check if discord is already in the list
			hasDiscord := false
			for _, n := range notificationsNode.Content {
				if n.Value == "discord" {
					hasDiscord = true
					break
				}
			}

			if !hasDiscord {
				notificationsNode.Content = append(notificationsNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: "discord"})
			}
		}
	} else {
		// Disable: remove discord from notifications if profile exists
		if profileNode != nil {
			notificationsNode, _ := findKey(profileNode, "notifications")
			if notificationsNode != nil && notificationsNode.Kind == yaml.SequenceNode {
				var newContent []*yaml.Node
				for _, n := range notificationsNode.Content {
					if n.Value != "discord" {
						newContent = append(newContent, n)
					}
				}
				notificationsNode.Content = newContent
				
				// Optional: remove notifications key if empty? 
				// Maybe better to leave it empty or remove it to be clean.
				// For now, leaving it empty is safer.
			}
		}
	}

	// Marshal back
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&node); err != nil {
		return fmt.Errorf("failed to marshal profiles.yaml: %v", err)
	}
	enc.Close()

	return os.WriteFile(path, buf.Bytes(), 0644)
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

	// Parse YAML into Node
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return fmt.Errorf("failed to parse docker-compose.yml: %w", err)
	}

	if len(node.Content) == 0 || node.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("docker-compose.yml root is not a mapping")
	}
	rootMap := node.Content[0]

	// Helper to find key in mapping
	findKey := func(parent *yaml.Node, key string) *yaml.Node {
		for i := 0; i < len(parent.Content); i += 2 {
			if parent.Content[i].Value == key {
				return parent.Content[i+1]
			}
		}
		return nil
	}

	// Navigate to services -> crowdsec
	servicesNode := findKey(rootMap, "services")
	if servicesNode == nil {
		return fmt.Errorf("services section not found")
	}

	crowdsecNode := findKey(servicesNode, "crowdsec")
	if crowdsecNode == nil {
		return fmt.Errorf("crowdsec service not found")
	}

	// Update environment variables
	// environment can be a sequence (list) or a mapping (dict).
	// We need to handle both or assume one. Docker Compose supports both.
	// The existing code assumed map[string]interface{}.
	// Let's check what it is.
	
	var envNode *yaml.Node
	for i := 0; i < len(crowdsecNode.Content); i += 2 {
		if crowdsecNode.Content[i].Value == "environment" {
			envNode = crowdsecNode.Content[i+1]
			break
		}
	}

	if envNode == nil {
		// Create environment as mapping
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "environment"}
		envNode = &yaml.Node{Kind: yaml.MappingNode}
		crowdsecNode.Content = append(crowdsecNode.Content, keyNode, envNode)
	}

	if envNode.Kind == yaml.MappingNode {
		// Helper to set scalar in map
		setScalar := func(parent *yaml.Node, key string, value string) {
			found := false
			for i := 0; i < len(parent.Content); i += 2 {
				if parent.Content[i].Value == key {
					parent.Content[i+1].Value = value
					found = true
					break
				}
			}
			if !found {
				parent.Content = append(parent.Content, 
					&yaml.Node{Kind: yaml.ScalarNode, Value: key},
					&yaml.Node{Kind: yaml.ScalarNode, Value: value},
				)
			}
		}

		setScalar(envNode, "GEOAPIFY_API_KEY", config.GeoapifyKey)
		setScalar(envNode, "DISCORD_WEBHOOK_ID", config.WebhookID)
		setScalar(envNode, "DISCORD_WEBHOOK_TOKEN", config.WebhookToken)
		if config.CTIKey != "" {
			setScalar(envNode, "CTI_API_KEY", config.CTIKey)
		}
	} else if envNode.Kind == yaml.SequenceNode {
		// Handle list format: - KEY=VALUE
		updateListEnv := func(key, value string) {
			prefix := key + "="
			found := false
			for _, item := range envNode.Content {
				if strings.HasPrefix(item.Value, prefix) {
					item.Value = fmt.Sprintf("%s=%s", key, value)
					found = true
					break
				}
			}
			if !found {
				envNode.Content = append(envNode.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: fmt.Sprintf("%s=%s", key, value)})
			}
		}

		updateListEnv("GEOAPIFY_API_KEY", config.GeoapifyKey)
		updateListEnv("DISCORD_WEBHOOK_ID", config.WebhookID)
		updateListEnv("DISCORD_WEBHOOK_TOKEN", config.WebhookToken)
		if config.CTIKey != "" {
			updateListEnv("CTI_API_KEY", config.CTIKey)
		}
	} else {
		return fmt.Errorf("environment section has unexpected format")
	}

	// Write back to file
	updatedData, err := yaml.Marshal(&node)
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

	// Parse YAML into Node
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return fmt.Errorf("failed to parse config.yaml: %w", err)
	}

	if len(node.Content) == 0 || node.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("config.yaml root is not a mapping")
	}
	rootMap := node.Content[0]

	// Find api section
	var apiNode *yaml.Node
	for i := 0; i < len(rootMap.Content); i += 2 {
		if rootMap.Content[i].Value == "api" {
			apiNode = rootMap.Content[i+1]
			break
		}
	}

	if apiNode == nil {
		// Create api section
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "api"}
		apiNode = &yaml.Node{Kind: yaml.MappingNode}
		rootMap.Content = append(rootMap.Content, keyNode, apiNode)
	}

	if apiNode.Kind != yaml.MappingNode {
		return fmt.Errorf("api section is not a mapping")
	}

	// Add CTI configuration
	ctiConfigYAML := `
key: "${CTI_API_KEY}"
cache_timeout: 60m
cache_size: 50
enabled: true
log_level: debug
`
	var ctiNode yaml.Node
	if err := yaml.Unmarshal([]byte(ctiConfigYAML), &ctiNode); err != nil {
		return fmt.Errorf("failed to parse cti config template: %v", err)
	}

	// Check if cti exists
	found := false
	for i := 0; i < len(apiNode.Content); i += 2 {
		if apiNode.Content[i].Value == "cti" {
			// Update existing? Or just leave it?
			// Let's overwrite it to ensure it's correct
			apiNode.Content[i+1] = ctiNode.Content[0]
			found = true
			break
		}
	}

	if !found {
		apiNode.Content = append(apiNode.Content, 
			&yaml.Node{Kind: yaml.ScalarNode, Value: "cti"},
			ctiNode.Content[0],
		)
	}

	// Write back to file
	updatedData, err := yaml.Marshal(&node)
	if err != nil {
		return fmt.Errorf("failed to marshal config.yaml: %w", err)
	}

	if err := os.WriteFile(configPath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write config.yaml: %w", err)
	}

	return nil
}
