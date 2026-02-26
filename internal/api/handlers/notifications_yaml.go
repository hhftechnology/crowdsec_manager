package handlers

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"gopkg.in/yaml.v3"
)

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
		"cat", cfg.CrowdSecNotificationsDir + "/discord.yaml",
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

	discordCfg := &models.DiscordConfig{}
	hasManualConfig := false

	// Extract URL and check if it has hardcoded values or template variables
	if urlStr, ok := yamlData["url"].(string); ok {
		if strings.Contains(urlStr, "discord.com/api/webhooks/") {
			if !strings.Contains(urlStr, "${DISCORD_WEBHOOK_ID}") && !strings.Contains(urlStr, "${DISCORD_WEBHOOK_TOKEN}") {
				parts := strings.Split(urlStr, "/")
				if len(parts) >= 7 {
					discordCfg.WebhookID = parts[5]
					discordCfg.WebhookToken = parts[6]
					hasManualConfig = true
				}
			}
		}
	}

	// Extract Geoapify key if hardcoded (not template variable)
	if formatStr, ok := yamlData["format"].(string); ok {
		if strings.Contains(formatStr, "geoapify") {
			if !strings.Contains(formatStr, "${GEOAPIFY_API_KEY}") && !strings.Contains(formatStr, "{{env \"GEOAPIFY_API_KEY\"}}") {
				re := regexp.MustCompile(`apiKey=([A-Za-z0-9_-]+)`)
				matches := re.FindStringSubmatch(formatStr)
				if len(matches) > 1 && matches[1] != "" {
					discordCfg.GeoapifyKey = matches[1]
					hasManualConfig = true
				}
			}
		}
	}

	discordCfg.ManuallyConfigured = hasManualConfig
	if hasManualConfig {
		logger.Info("Detected manually configured discord.yaml in container")
	}

	return discordCfg, nil
}

// isDiscordEnabled checks if discord notifications are enabled in profiles.yaml
func isDiscordEnabled(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	var profiles map[string]interface{}
	if err := yaml.Unmarshal(data, &profiles); err != nil {
		return false, err
	}

	return strings.Contains(string(data), "- discord"), nil
}

// updateProfilesYaml updates profiles.yaml to enable/disable discord notifications
// This function properly handles multiple YAML documents separated by "---"
// It works with ANY user-defined profiles and adds notifications to profiles with IP-based decisions
func updateProfilesYaml(path string, enable bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && enable {
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
	shouldHaveNotifications := func(profileNode *yaml.Node) bool {
		if profileNode.Kind != yaml.MappingNode {
			return false
		}

		nameNode, _ := findKey(profileNode, "name")
		if nameNode == nil {
			return false
		}

		name := strings.ToLower(nameNode.Value)
		if strings.Contains(name, "captcha") && !strings.Contains(name, "ip") {
			return false
		}

		if strings.Contains(name, "range") && !strings.Contains(name, "ip") {
			return false
		}

		decisionsNode, _ := findKey(profileNode, "decisions")
		if decisionsNode == nil {
			return false
		}

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

		if !shouldHaveNotifications(profileNode) {
			return false, profileName
		}

		if enable {
			notificationsNode, notifIdx := findKey(profileNode, "notifications")
			if notificationsNode == nil {
				keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "notifications"}
				notificationsNode = &yaml.Node{
					Kind:  yaml.SequenceNode,
					Style: yaml.FlowStyle,
				}
				profileNode.Content = append(profileNode.Content, keyNode, notificationsNode)
			} else if notificationsNode.Kind != yaml.SequenceNode {
				notificationsNode.Kind = yaml.SequenceNode
				notificationsNode.Style = yaml.FlowStyle
				notificationsNode.Content = []*yaml.Node{}
				profileNode.Content[notifIdx] = notificationsNode
			}

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
			if len(documents) == 0 && len(data) == 0 {
				break
			}
			return fmt.Errorf("failed to parse profiles.yaml: %v", err)
		}

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
			Kind:    yaml.DocumentNode,
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

