package handlers

import (
	"fmt"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"

	"gopkg.in/yaml.v3"
)

// updateCrowdSecProfiles updates CrowdSec profiles.yaml to include captcha remediation
func updateCrowdSecProfiles(dockerClient *docker.Client, cfg *config.Config) error {
	// Read current profiles.yaml
	output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"cat", cfg.CrowdSecProfilesPath,
	})
	if err != nil {
		return fmt.Errorf("failed to read profiles.yaml: %v", err)
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

	// Parse multiple YAML documents (profiles.yaml can have multiple documents separated by ---)
	decoder := yaml.NewDecoder(strings.NewReader(output))
	var documents []*yaml.Node
	foundProfile := false

	for {
		var doc yaml.Node
		err := decoder.Decode(&doc)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			if len(documents) == 0 && len(output) == 0 {
				break
			}
			return fmt.Errorf("failed to parse profiles.yaml: %v", err)
		}

		// Process this document
		if len(doc.Content) > 0 && doc.Content[0].Kind == yaml.MappingNode {
			profileNode := doc.Content[0]
			nameNode, _ := findKey(profileNode, "name")

			// Check if this is the default_ip_remediation profile
			if nameNode != nil && nameNode.Value == "default_ip_remediation" {
				foundProfile = true

				// Find decisions node
				decisionsNode, _ := findKey(profileNode, "decisions")
				if decisionsNode == nil {
					keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: "decisions"}
					decisionsNode = &yaml.Node{Kind: yaml.SequenceNode}
					profileNode.Content = append(profileNode.Content, keyNode, decisionsNode)
				}

				// Check if captcha decision exists
				hasCaptcha := false
				if decisionsNode.Kind == yaml.SequenceNode {
					for _, decision := range decisionsNode.Content {
						if decision.Kind == yaml.MappingNode {
							typeNode, _ := findKey(decision, "type")
							if typeNode != nil && typeNode.Value == "captcha" {
								hasCaptcha = true
								break
							}
						}
					}
				}

				if !hasCaptcha {
					captchaDecision := &yaml.Node{
						Kind: yaml.MappingNode,
						Content: []*yaml.Node{
							{Kind: yaml.ScalarNode, Value: "type"},
							{Kind: yaml.ScalarNode, Value: "captcha"},
							{Kind: yaml.ScalarNode, Value: "duration"},
							{Kind: yaml.ScalarNode, Value: "4h"},
						},
					}
					decisionsNode.Content = append(decisionsNode.Content, captchaDecision)
					logger.Info("Added captcha decision to default_ip_remediation profile")
				}
			}
		}

		documents = append(documents, &doc)
	}

	// If profile not found, create it
	if !foundProfile {
		logger.Info("Creating default_ip_remediation profile with captcha")
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
					{Kind: yaml.MappingNode, Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Value: "type"},
						{Kind: yaml.ScalarNode, Value: "captcha"},
						{Kind: yaml.ScalarNode, Value: "duration"},
						{Kind: yaml.ScalarNode, Value: "4h"},
					}},
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
	var buf strings.Builder
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)

	for i, doc := range documents {
		if err := encoder.Encode(doc); err != nil {
			return fmt.Errorf("failed to marshal profiles.yaml document %d: %v", i, err)
		}
	}
	encoder.Close()

	// Clean up output
	newProfileBytes := buf.String()
	newProfileBytes = strings.TrimPrefix(newProfileBytes, "---\n")

	// Backup existing profiles.yaml
	_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"cp", cfg.CrowdSecProfilesPath, cfg.CrowdSecProfilesPath + ".bak",
	})

	// Write new profiles.yaml using Docker copy API (no shell interpolation)
	err = dockerClient.WriteFileToContainer(cfg.CrowdsecContainerName, cfg.CrowdSecProfilesPath, []byte(newProfileBytes))
	if err != nil {
		// Restore backup if failed
		_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"mv", cfg.CrowdSecProfilesPath + ".bak", cfg.CrowdSecProfilesPath,
		})
		return fmt.Errorf("failed to write profiles.yaml: %v", err)
	}

	// Reload profiles
	_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"cscli", "profiles", "reload",
	})

	logger.Info("CrowdSec profiles updated successfully")
	return nil
}

// verifyCaptchaSetup verifies that captcha is properly configured
func verifyCaptchaSetup(dockerClient *docker.Client, cfg *config.Config) bool {
	// Check 1: Captcha HTML exists in Traefik container
	exists, err := dockerClient.FileExists(cfg.TraefikContainerName, cfg.TraefikCaptchaHTMLPath)
	if err != nil || !exists {
		logger.Warn("Captcha HTML verification failed", "path", cfg.TraefikCaptchaHTMLPath, "exists", exists, "error", err)
		return false
	}
	logger.Info("Captcha HTML file verified", "path", cfg.TraefikCaptchaHTMLPath)

	// Check 2: Dynamic config contains captcha settings
	configContent, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
		"cat", cfg.TraefikDynamicConfig,
	})
	if err != nil {
		logger.Warn("Failed to read dynamic config for verification", "error", err)
		return false
	}

	if !strings.Contains(strings.ToLower(configContent), "captcha") {
		logger.Warn("Captcha not found in dynamic config")
		return false
	}
	logger.Info("Dynamic config contains captcha settings")

	// Check 3: Dynamic config references correct captcha.html path
	if !strings.Contains(configContent, cfg.TraefikCaptchaHTMLPath) {
		logger.Warn("Dynamic config does not reference correct captcha.html path")
		return false
	}
	logger.Info("Dynamic config references correct captcha.html path")

	// Check 4: CrowdSec profiles contain captcha decision
	profilesContent, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"cat", cfg.CrowdSecProfilesPath,
	})
	if err != nil {
		logger.Warn("Failed to read profiles for verification", "error", err)
		return false
	}

	if !strings.Contains(strings.ToLower(profilesContent), "captcha") {
		logger.Warn("Captcha not found in CrowdSec profiles")
		return false
	}
	logger.Info("CrowdSec profiles contain captcha decision")

	logger.Info("Captcha setup verification passed - all checks OK")
	return true
}
