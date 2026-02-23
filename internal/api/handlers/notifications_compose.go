package handlers

import (
	"fmt"
	"os"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"gopkg.in/yaml.v3"
)

// generateDiscordYamlInContainer writes discord.yaml directly to CrowdSec container config
func generateDiscordYamlInContainer(dockerClient *docker.Client, cfg *config.Config, discordCfg models.DiscordConfig) error {
	// Create notifications directory if it doesn't exist
	_, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"mkdir", "-p", cfg.CrowdSecNotificationsDir,
	})
	if err != nil {
		logger.Warn("Failed to create notifications directory (may already exist)", "error", err)
	}

	// Escape single quotes in the template for shell command
	escapedTemplate := strings.ReplaceAll(DiscordTemplate, "'", "'\\''")

	// Write discord.yaml directly to container
	_, err = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"sh", "-c", fmt.Sprintf("echo '%s' > %s/discord.yaml", escapedTemplate, cfg.CrowdSecNotificationsDir),
	})
	if err != nil {
		return fmt.Errorf("failed to write discord.yaml to container: %w", err)
	}

	logger.Info("Discord YAML created in CrowdSec container", "path", cfg.CrowdSecNotificationsDir+"/discord.yaml")
	return nil
}

// updateDockerComposeEnvOnly updates docker-compose.yml to add Discord environment variables ONLY (no volume mount)
func updateDockerComposeEnvOnly(composePath string, discordCfg models.DiscordConfig) error {
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
	var envNode *yaml.Node
	for i := 0; i < len(crowdsecNode.Content); i += 2 {
		if crowdsecNode.Content[i].Value == "environment" {
			envNode = crowdsecNode.Content[i+1]
			break
		}
	}

	if envNode == nil {
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "environment"}
		envNode = &yaml.Node{Kind: yaml.MappingNode}
		crowdsecNode.Content = append(crowdsecNode.Content, keyNode, envNode)
	}

	if envNode.Kind == yaml.MappingNode {
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

		setScalar(envNode, "GEOAPIFY_API_KEY", discordCfg.GeoapifyKey)
		setScalar(envNode, "DISCORD_WEBHOOK_ID", discordCfg.WebhookID)
		setScalar(envNode, "DISCORD_WEBHOOK_TOKEN", discordCfg.WebhookToken)
		if discordCfg.CrowdSecCTIKey != "" {
			setScalar(envNode, "CROWDSEC_CTI_API_KEY", discordCfg.CrowdSecCTIKey)
		}
	} else if envNode.Kind == yaml.SequenceNode {
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

		updateListEnv("GEOAPIFY_API_KEY", discordCfg.GeoapifyKey)
		updateListEnv("DISCORD_WEBHOOK_ID", discordCfg.WebhookID)
		updateListEnv("DISCORD_WEBHOOK_TOKEN", discordCfg.WebhookToken)
		if discordCfg.CrowdSecCTIKey != "" {
			updateListEnv("CROWDSEC_CTI_API_KEY", discordCfg.CrowdSecCTIKey)
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
func createOrUpdateEnvFile(envPath string, discordCfg models.DiscordConfig) error {
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
	envVars["GEOAPIFY_API_KEY"] = discordCfg.GeoapifyKey
	envVars["DISCORD_WEBHOOK_ID"] = discordCfg.WebhookID
	envVars["DISCORD_WEBHOOK_TOKEN"] = discordCfg.WebhookToken
	if discordCfg.CrowdSecCTIKey != "" {
		envVars["CROWDSEC_CTI_API_KEY"] = discordCfg.CrowdSecCTIKey
	}

	// Build new .env content
	var lines []string
	lines = append(lines, "# Discord Notification Configuration")
	lines = append(lines, fmt.Sprintf("GEOAPIFY_API_KEY=%s", envVars["GEOAPIFY_API_KEY"]))
	lines = append(lines, fmt.Sprintf("DISCORD_WEBHOOK_ID=%s", envVars["DISCORD_WEBHOOK_ID"]))
	lines = append(lines, fmt.Sprintf("DISCORD_WEBHOOK_TOKEN=%s", envVars["DISCORD_WEBHOOK_TOKEN"]))
	if discordCfg.CrowdSecCTIKey != "" {
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
		return nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config.yaml: %w", err)
	}

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

	updatedData, err := yaml.Marshal(&node)
	if err != nil {
		return fmt.Errorf("failed to marshal config.yaml: %w", err)
	}

	if err := os.WriteFile(configPath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write config.yaml: %w", err)
	}

	return nil
}
