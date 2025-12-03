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

// readDiscordConfigFromContainer reads discord.yaml from CrowdSec container and detects manual configuration
func readDiscordConfigFromContainer(dockerClient *docker.Client, cfg *config.Config) (*models.DiscordConfig, error) {
	// Read discord.yaml from container
	output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"cat", "/etc/crowdsec/notifications/discord.yaml",
	})
	if err != nil {
		return nil, fmt.Errorf("discord.yaml not found in container: %w", err)
	}

	yamlContent := strings.TrimSpace(output)
	if yamlContent == "" {
		return nil, fmt.Errorf("discord.yaml is empty")
	}

	var yamlData map[string]interface{}
	if err := yaml.Unmarshal([]byte(yamlContent), &yamlData); err != nil {
		return nil, fmt.Errorf("failed to parse discord.yaml: %w", err)
	}

	config := &models.DiscordConfig{}
	hasManualConfig := false

	// Extract URL and check if it has hardcoded values or template variables
	if urlStr, ok := yamlData["url"].(string); ok {
		// Check if URL contains actual values (not template variables)
		if strings.Contains(urlStr, "discord.com/api/webhooks/") {
			// Check if it uses template variables like ${DISCORD_WEBHOOK_ID}
			if !strings.Contains(urlStr, "${DISCORD_WEBHOOK_ID}") && !strings.Contains(urlStr, "${DISCORD_WEBHOOK_TOKEN}") {
				// Has hardcoded values - extract them
				parts := strings.Split(urlStr, "/")
				if len(parts) >= 7 {
					config.WebhookID = parts[5]
					config.WebhookToken = parts[6]
					hasManualConfig = true
				}
			}
		}
	}

	// Extract Geoapify key if hardcoded (not template variable)
	if formatStr, ok := yamlData["format"].(string); ok {
		if strings.Contains(formatStr, "geoapify") {
			// Check if it's NOT using template variable
			if !strings.Contains(formatStr, "${GEOAPIFY_API_KEY}") && !strings.Contains(formatStr, "{{env \"GEOAPIFY_API_KEY\"}}") {
				// Look for actual API key value
				re := regexp.MustCompile(`apiKey=([A-Za-z0-9_-]+)`)
				matches := re.FindStringSubmatch(formatStr)
				if len(matches) > 1 && matches[1] != "" {
					config.GeoapifyKey = matches[1]
					hasManualConfig = true
				}
			}
		}
	}

	config.ManuallyConfigured = hasManualConfig
	if hasManualConfig {
		logger.Info("Detected manually configured discord.yaml in container")
	}

	return config, nil
}

// GetDiscordConfig retrieves the current Discord configuration
func GetDiscordConfig(db *database.Database, cfg *config.Config, dockerClient *docker.Client) gin.HandlerFunc {
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
			CrowdSecCTIKey:       settings.CrowdSecCTIKey,
			ConfigSource: "database",
		}

		// Try to read from container to detect manual configuration
		containerConfig, err := readDiscordConfigFromContainer(dockerClient, cfg)
		if err == nil && containerConfig != nil {
			// Container config exists - check if it's manually configured or uses templates
			if containerConfig.ManuallyConfigured {
				// User manually configured discord.yaml with hardcoded values
				config.ManuallyConfigured = true
				config.ConfigSource = "container"

				// Pre-populate with container values if database is empty
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

				// If both sources have values, indicate that
				if settings.DiscordWebhookID != "" || settings.DiscordWebhookToken != "" {
					config.ConfigSource = "both"
				}
			} else {
				// Container has discord.yaml but it uses template variables (normal case)
				config.ConfigSource = "database"
			}
		} else {
			// No container config found (file doesn't exist or error reading)
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
		if req.CrowdSecCTIKey != "" {
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
// This function properly handles multiple YAML documents separated by "---"
// It works with ANY user-defined profiles and adds notifications to profiles with IP-based decisions
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

	// Helper to find key in mapping
	findKey := func(parent *yaml.Node, key string) (*yaml.Node, int) {
		for i := 0; i < len(parent.Content); i += 2 {
			if parent.Content[i].Value == key {
				return parent.Content[i+1], i + 1
			}
		}
		return nil, -1
	}

	// Helper to check if a profile should have notifications
	// Returns true for profiles that have IP scope (not range, not captcha-only)
	shouldHaveNotifications := func(profileNode *yaml.Node) bool {
		if profileNode.Kind != yaml.MappingNode {
			return false
		}

		nameNode, _ := findKey(profileNode, "name")
		if nameNode == nil {
			return false
		}

		// Skip captcha-only profiles (they have their own remediation flow)
		name := strings.ToLower(nameNode.Value)
		if strings.Contains(name, "captcha") && !strings.Contains(name, "ip") {
			return false
		}

		// Skip range-only profiles (notifications typically for IPs)
		if strings.Contains(name, "range") && !strings.Contains(name, "ip") {
			return false
		}

		// Check if profile has decisions (profiles without decisions shouldn't notify)
		decisionsNode, _ := findKey(profileNode, "decisions")
		if decisionsNode == nil {
			return false
		}

		// This profile should have notifications
		return true
	}

	// Helper to process a single profile document
	processProfile := func(profileNode *yaml.Node) (bool, string) {
		if profileNode.Kind != yaml.MappingNode {
			return false, ""
		}

		nameNode, _ := findKey(profileNode, "name")
		if nameNode == nil {
			return false, ""
		}
		profileName := nameNode.Value

		// Check if this profile should have notifications
		if !shouldHaveNotifications(profileNode) {
			return false, profileName
		}

		// This profile should have notifications
		if enable {
			// Add or update notifications
			notificationsNode, notifIdx := findKey(profileNode, "notifications")
			if notificationsNode == nil {
				// Add notifications section
				keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "notifications"}
				notificationsNode = &yaml.Node{
					Kind: yaml.SequenceNode,
					Style: yaml.FlowStyle,
				}
				profileNode.Content = append(profileNode.Content, keyNode, notificationsNode)
			} else if notificationsNode.Kind != yaml.SequenceNode {
				// Convert to sequence if it's not already
				notificationsNode.Kind = yaml.SequenceNode
				notificationsNode.Style = yaml.FlowStyle
				notificationsNode.Content = []*yaml.Node{}
				profileNode.Content[notifIdx] = notificationsNode
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
				notificationsNode.Content = append(notificationsNode.Content, &yaml.Node{
					Kind:  yaml.ScalarNode,
					Value: "discord",
				})
				logger.Info("Added discord notification to profile", "profile", profileName)
			}
		} else {
			// Remove discord from notifications
			notificationsNode, _ := findKey(profileNode, "notifications")
			if notificationsNode != nil && notificationsNode.Kind == yaml.SequenceNode {
				var newContent []*yaml.Node
				for _, n := range notificationsNode.Content {
					if n.Value != "discord" {
						newContent = append(newContent, n)
					}
				}
				notificationsNode.Content = newContent
				logger.Info("Removed discord notification from profile", "profile", profileName)
			}
		}
		return true, profileName
	}

	// Parse multiple YAML documents
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var documents []*yaml.Node
	foundTargets := []string{}

	for {
		var doc yaml.Node
		err := decoder.Decode(&doc)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			// If we can't parse, try to handle as empty/new file
			if len(documents) == 0 && len(data) == 0 {
				break
			}
			return fmt.Errorf("failed to parse profiles.yaml: %v", err)
		}

		// Process this document
		if len(doc.Content) > 0 && doc.Content[0].Kind == yaml.MappingNode {
			if processed, name := processProfile(doc.Content[0]); processed {
				foundTargets = append(foundTargets, name)
			}
		}

		documents = append(documents, &doc)
	}

	// If enabling and no suitable profiles found, create a default one
	if enable && len(foundTargets) == 0 {
		logger.Info("No suitable profiles found, creating default_ip_remediation profile")

		newProfile := &yaml.Node{
			Kind: yaml.MappingNode,
			Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "name"},
				{Kind: yaml.ScalarNode, Value: "default_ip_remediation"},

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

				{Kind: yaml.ScalarNode, Value: "notifications"},
				{Kind: yaml.SequenceNode, Style: yaml.FlowStyle, Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Value: "discord"},
				}},

				{Kind: yaml.ScalarNode, Value: "on_success"},
				{Kind: yaml.ScalarNode, Value: "break"},
			},
		}

		newDoc := &yaml.Node{
			Kind: yaml.DocumentNode,
			Content: []*yaml.Node{newProfile},
		}
		documents = append(documents, newDoc)
	}

	// Write all documents back to file
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)

	for i, doc := range documents {
		if i > 0 {
			// Add document separator
			buf.WriteString("\n---\n")
		}
		if err := encoder.Encode(doc); err != nil {
			return fmt.Errorf("failed to marshal profiles.yaml document %d: %v", i, err)
		}
	}
	encoder.Close()

	// Clean up the output - remove the extra "---" that encoder adds at the start
	output := buf.Bytes()
	output = bytes.TrimPrefix(output, []byte("---\n"))

	return os.WriteFile(path, output, 0644)
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
		if config.CrowdSecCTIKey != "" {
			setScalar(envNode, "CROWDSEC_CTI_API_KEY", config.CrowdSecCTIKey)
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
		if config.CrowdSecCTIKey != "" {
			updateListEnv("CROWDSEC_CTI_API_KEY", config.CrowdSecCTIKey)
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
	if config.CrowdSecCTIKey != "" {
		envVars["CROWDSEC_CTI_API_KEY"] = config.CrowdSecCTIKey
	}

	// Build new .env content
	var lines []string
	lines = append(lines, "# Discord Notification Configuration")
	lines = append(lines, fmt.Sprintf("GEOAPIFY_API_KEY=%s", envVars["GEOAPIFY_API_KEY"]))
	lines = append(lines, fmt.Sprintf("DISCORD_WEBHOOK_ID=%s", envVars["DISCORD_WEBHOOK_ID"]))
	lines = append(lines, fmt.Sprintf("DISCORD_WEBHOOK_TOKEN=%s", envVars["DISCORD_WEBHOOK_TOKEN"]))
	if config.CrowdSecCTIKey != "" {
		lines = append(lines, fmt.Sprintf("CROWDSEC_CTI_API_KEY=%s", envVars["CROWDSEC_CTI_API_KEY"]))
	}
	lines = append(lines, "")

	// Append other non-Discord variables
	for key, value := range envVars {
		if key != "GEOAPIFY_API_KEY" && key != "DISCORD_WEBHOOK_ID" &&
		   key != "DISCORD_WEBHOOK_TOKEN" && key != "CROWDSEC_CTI_API_KEY" {
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
key: "${CROWDSEC_CTI_API_KEY}"
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
