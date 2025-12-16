package traefik

import (
	"context"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/proxy"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// TraefikCaptchaManager implements CaptchaManager for Traefik
type TraefikCaptchaManager struct {
	dockerClient *docker.Client
	cfg          *config.Config
}

// NewTraefikCaptchaManager creates a new Traefik captcha manager
func NewTraefikCaptchaManager(dockerClient *docker.Client, cfg *config.Config) *TraefikCaptchaManager {
	return &TraefikCaptchaManager{
		dockerClient: dockerClient,
		cfg:          cfg,
	}
}

// Captcha HTML template for Cloudflare Turnstile
const captchaHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Verification</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        .container {
            background: white;
            border-radius: 10px;
            padding: 40px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            max-width: 500px;
            text-align: center;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
        }
        p {
            color: #666;
            margin-bottom: 30px;
        }
        .cf-turnstile {
            display: inline-block;
            margin: 20px 0;
        }
        #error {
            color: #e53e3e;
            margin-top: 20px;
            display: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Security Verification</h1>
        <p>Please complete the security check below to continue</p>
        <form id="captcha-form" action="{{.RedirectURL}}" method="POST">
            <div class="cf-turnstile" data-sitekey="{{.SiteKey}}" data-callback="onCaptchaSuccess"></div>
            <input type="hidden" name="crowdsec_captcha" value="{{.CaptchaValue}}">
        </form>
        <div id="error"></div>
    </div>
    <script>
        function onCaptchaSuccess(token) {
            document.getElementById('captcha-form').submit();
        }
    </script>
</body>
</html>`

// SetupCaptcha sets up Cloudflare Turnstile captcha for Traefik
func (t *TraefikCaptchaManager) SetupCaptcha(ctx context.Context, req *models.CaptchaSetupRequest) error {
	logger.Info("Setting up Traefik captcha", "provider", req.Provider, "site_key", req.SiteKey)
	
	// Validate inputs
	if req.SiteKey == "" || req.SecretKey == "" {
		return fmt.Errorf("site key and secret key are required")
	}
	
	// STEP 1: Create captcha.html file on host
	logger.Info("Creating captcha.html file")
	captchaHTML := strings.ReplaceAll(captchaHTMLTemplate, "{{.SiteKey}}", req.SiteKey)
	captchaHTML = strings.ReplaceAll(captchaHTML, "{{.RedirectURL}}", "")
	captchaHTML = strings.ReplaceAll(captchaHTML, "{{.CaptchaValue}}", "")

	// Use local path for Traefik config directory (mapped via /app/config)
	traefikConfigDir := filepath.Join(t.cfg.ConfigDir, "traefik")
	
	// Verify the directory exists
	if _, err := os.Stat(traefikConfigDir); err != nil {
		return fmt.Errorf("traefik configuration directory not found at %s: %w", traefikConfigDir, err)
	}

	// Create conf directory if it doesn't exist
	confDir := filepath.Join(traefikConfigDir, "conf")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		return fmt.Errorf("failed to create conf directory: %w", err)
	}
	logger.Info("Ensured conf directory exists", "path", confDir)

	// Write captcha.html to conf directory
	captchaHTMLPath := filepath.Join(confDir, "captcha.html")
	if err := os.WriteFile(captchaHTMLPath, []byte(captchaHTML), 0644); err != nil {
		return fmt.Errorf("failed to create captcha.html: %w", err)
	}
	logger.Info("Captcha HTML file created", "path", captchaHTMLPath)

	// STEP 2: Update Traefik dynamic_config.yml
	logger.Info("Updating Traefik dynamic configuration")
	if err := t.updateTraefikCaptchaConfig(req, traefikConfigDir); err != nil {
		return fmt.Errorf("failed to update Traefik configuration: %w", err)
	}

	// STEP 3: Update CrowdSec profiles.yaml
	logger.Info("Updating CrowdSec profiles")
	if err := t.updateCrowdSecProfiles(); err != nil {
		return fmt.Errorf("failed to update CrowdSec profiles: %w", err)
	}

	// STEP 4: Restart Traefik container
	logger.Info("Restarting Traefik container")
	if err := t.dockerClient.RestartContainer(t.cfg.TraefikContainerName); err != nil {
		logger.Warn("Failed to restart Traefik", "error", err)
	} else {
		logger.Info("Traefik restarted successfully")
		time.Sleep(3 * time.Second) // Wait for Traefik to be ready
	}

	// STEP 5: Restart CrowdSec container
	logger.Info("Restarting CrowdSec container")
	if err := t.dockerClient.RestartContainer(t.cfg.CrowdsecContainerName); err != nil {
		logger.Warn("Failed to restart CrowdSec", "error", err)
	} else {
		logger.Info("CrowdSec restarted successfully")
		time.Sleep(3 * time.Second) // Wait for CrowdSec to be ready
	}

	logger.Info("Captcha setup completed successfully")
	return nil
}

// GetCaptchaStatus retrieves the current captcha configuration status
func (t *TraefikCaptchaManager) GetCaptchaStatus(ctx context.Context) (*proxy.CaptchaStatus, error) {
	logger.Info("Getting Traefik captcha status")

	// Check dynamic_config.yml for captcha configuration
	configContent, err := t.dockerClient.ExecCommand(t.cfg.TraefikContainerName, []string{
		"cat", "/etc/traefik/dynamic_config.yml",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read dynamic config: %w", err)
	}

	configured := false
	provider := ""
	siteKey := ""
	
	if configContent != "" {
		configured, provider = t.detectCaptchaInConfig(configContent)
		siteKey = t.extractSiteKey(configContent)
	}

	// Check if captcha.html exists in Traefik container
	captchaHTMLExists := false
	exists, err := t.dockerClient.FileExists(t.cfg.TraefikContainerName, "/etc/traefik/conf/captcha.html")
	if err == nil && exists {
		captchaHTMLExists = true
	}

	return &proxy.CaptchaStatus{
		Enabled:  configured && captchaHTMLExists,
		Provider: provider,
		SiteKey:  siteKey,
	}, nil
}

// DisableCaptcha disables captcha configuration
func (t *TraefikCaptchaManager) DisableCaptcha(ctx context.Context) error {
	logger.Info("Disabling Traefik captcha")
	
	// Remove captcha.html file
	_, err := t.dockerClient.ExecCommand(t.cfg.TraefikContainerName, []string{
		"rm", "-f", "/etc/traefik/conf/captcha.html",
	})
	if err != nil {
		logger.Warn("Failed to remove captcha.html", "error", err)
	}
	
	// TODO: Remove captcha configuration from dynamic_config.yml
	// This would require more complex YAML manipulation
	
	logger.Info("Captcha disabled successfully")
	return nil
}

// detectCaptchaInConfig checks if captcha is configured in dynamic_config.yml
func (t *TraefikCaptchaManager) detectCaptchaInConfig(configContent string) (enabled bool, provider string) {
	configLower := strings.ToLower(configContent)

	// Check if captcha keys exist
	if strings.Contains(configLower, "captchaprovider") || strings.Contains(configLower, "captchasitekey") {
		enabled = true

		// Detect provider
		if strings.Contains(configLower, "turnstile") {
			provider = "turnstile"
		} else if strings.Contains(configLower, "recaptcha") {
			provider = "recaptcha"
		} else if strings.Contains(configLower, "hcaptcha") {
			provider = "hcaptcha"
		} else {
			provider = "unknown"
		}
	}

	return
}

// extractSiteKey extracts site key from dynamic_config.yml content
func (t *TraefikCaptchaManager) extractSiteKey(configContent string) string {
	// Parse YAML to extract site key
	var config map[string]interface{}
	if err := yaml.Unmarshal([]byte(configContent), &config); err != nil {
		return ""
	}

	// Navigate: http -> middlewares -> (any) -> plugin -> (crowdsec*)
	if http, ok := config["http"].(map[string]interface{}); ok {
		if middlewares, ok := http["middlewares"].(map[string]interface{}); ok {
			// Iterate over all middlewares to find the one with CrowdSec plugin
			for _, mw := range middlewares {
				if mwMap, ok := mw.(map[string]interface{}); ok {
					if plugin, ok := mwMap["plugin"].(map[string]interface{}); ok {
						// Check for crowdsec plugin (key containing "crowdsec")
						for k, v := range plugin {
							if strings.Contains(strings.ToLower(k), "crowdsec") {
								if crowdsec, ok := v.(map[string]interface{}); ok {
									// Extract site key from flat structure
									if key, ok := crowdsec["captchaSiteKey"].(string); ok {
										return key
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return ""
}

// updateTraefikCaptchaConfig updates Traefik's dynamic_config.yml with captcha configuration
func (t *TraefikCaptchaManager) updateTraefikCaptchaConfig(req *models.CaptchaSetupRequest, traefikConfigDir string) error {
	// Read existing config from local filesystem
	dynamicConfigPath := filepath.Join(traefikConfigDir, "dynamic_config.yml")

	configBytes, err := os.ReadFile(dynamicConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read dynamic_config.yml from local path: %w", err)
	}

	// Parse YAML into Node to preserve comments
	var node yaml.Node
	if err := yaml.Unmarshal(configBytes, &node); err != nil {
		return fmt.Errorf("failed to parse dynamic_config.yml: %w", err)
	}

	// Ensure root is a mapping
	if len(node.Content) == 0 {
		// Empty file, initialize
		node.Kind = yaml.DocumentNode
		node.Content = []*yaml.Node{
			{Kind: yaml.MappingNode},
		}
	} else if node.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("dynamic_config.yml root is not a mapping")
	}
	rootMap := node.Content[0]

	// Helper to find or create a key in a mapping
	findOrCreateMap := func(parent *yaml.Node, key string) *yaml.Node {
		for i := 0; i < len(parent.Content); i += 2 {
			if parent.Content[i].Value == key {
				if parent.Content[i+1].Kind != yaml.MappingNode {
					parent.Content[i+1] = &yaml.Node{Kind: yaml.MappingNode}
				}
				return parent.Content[i+1]
			}
		}
		// Not found, create it
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
		valNode := &yaml.Node{Kind: yaml.MappingNode}
		parent.Content = append(parent.Content, keyNode, valNode)
		return valNode
	}

	// Navigate/Create structure: http -> middlewares
	httpNode := findOrCreateMap(rootMap, "http")
	middlewaresNode := findOrCreateMap(httpNode, "middlewares")

	// Find or create crowdsec bouncer middleware
	var crowdsecPluginNode *yaml.Node

	// Search existing
	for i := 0; i < len(middlewaresNode.Content); i += 2 {
		mwBody := middlewaresNode.Content[i+1]
		
		// Check if this middleware has the plugin
		for j := 0; j < len(mwBody.Content); j += 2 {
			if mwBody.Content[j].Value == "plugin" {
				pluginBody := mwBody.Content[j+1]
				for k := 0; k < len(pluginBody.Content); k += 2 {
					if strings.Contains(strings.ToLower(pluginBody.Content[k].Value), "crowdsec") {
						crowdsecPluginNode = pluginBody.Content[k+1]
						break
					}
				}
			}
			if crowdsecPluginNode != nil {
				break
			}
		}
		if crowdsecPluginNode != nil {
			break
		}
	}

	// If not found, create it
	if crowdsecPluginNode == nil {
		mwName := "crowdsec-bouncer-traefik-plugin"
		middlewareNode := findOrCreateMap(middlewaresNode, mwName)
		pluginNode := findOrCreateMap(middlewareNode, "plugin")
		crowdsecPluginNode = findOrCreateMap(pluginNode, "crowdsec-bouncer-traefik-plugin")
	}

	// Helper to set a value in a mapping
	setScalar := func(parent *yaml.Node, key string, value string, tag string) {
		found := false
		for i := 0; i < len(parent.Content); i += 2 {
			if parent.Content[i].Value == key {
				parent.Content[i+1].Value = value
				if tag != "" {
					parent.Content[i+1].Tag = tag
				}
				found = true
				break
			}
		}
		if !found {
			keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
			valNode := &yaml.Node{Kind: yaml.ScalarNode, Value: value}
			if tag != "" {
				valNode.Tag = tag
			}
			parent.Content = append(parent.Content, keyNode, valNode)
		}
	}

	// Update captcha configuration (Flat structure)
	provider := "turnstile"
	if req.Provider != "" {
		provider = req.Provider
	}
	
	setScalar(crowdsecPluginNode, "captchaProvider", provider, "")
	setScalar(crowdsecPluginNode, "captchaSiteKey", req.SiteKey, "")
	setScalar(crowdsecPluginNode, "captchaSecretKey", req.SecretKey, "")
	setScalar(crowdsecPluginNode, "captchaHTMLFilePath", "/etc/traefik/conf/captcha.html", "")
	setScalar(crowdsecPluginNode, "captchaGracePeriodSeconds", "1800", "!!int")

	// Create backup before modifying
	backupPath := dynamicConfigPath + ".bak"
	if err := os.WriteFile(backupPath, configBytes, 0644); err != nil {
		logger.Warn("Failed to create backup of dynamic_config.yml", "error", err)
	}

	// Marshal back to YAML
	newConfigBytes, err := yaml.Marshal(&node)
	if err != nil {
		return fmt.Errorf("failed to marshal dynamic_config.yml: %w", err)
	}

	// Write updated config to host filesystem
	if err := os.WriteFile(dynamicConfigPath, newConfigBytes, 0644); err != nil {
		// Restore backup if write fails
		if backupBytes, err2 := os.ReadFile(backupPath); err2 == nil {
			os.WriteFile(dynamicConfigPath, backupBytes, 0644)
		}
		return fmt.Errorf("failed to write dynamic_config.yml to local path: %w", err)
	}

	logger.Info("Traefik dynamic config updated successfully")
	return nil
}

// updateCrowdSecProfiles updates CrowdSec profiles.yaml to include captcha remediation
func (t *TraefikCaptchaManager) updateCrowdSecProfiles() error {
	// Read current profiles.yaml
	output, err := t.dockerClient.ExecCommand(t.cfg.CrowdsecContainerName, []string{
		"cat", "/etc/crowdsec/profiles.yaml",
	})
	if err != nil {
		return fmt.Errorf("failed to read profiles.yaml: %w", err)
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

	// Parse multiple YAML documents
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
			return fmt.Errorf("failed to parse profiles.yaml: %w", err)
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
					// Add decisions key
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
					// Add captcha decision
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
		if i > 0 {
			buf.WriteString("\n---\n")
		}
		if err := encoder.Encode(doc); err != nil {
			return fmt.Errorf("failed to marshal profiles.yaml document %d: %w", i, err)
		}
	}
	encoder.Close()

	// Clean up output
	newProfileBytes := buf.String()
	newProfileBytes = strings.TrimPrefix(newProfileBytes, "---\n")

	// Backup existing profiles.yaml
	_, _ = t.dockerClient.ExecCommand(t.cfg.CrowdsecContainerName, []string{
		"cp", "/etc/crowdsec/profiles.yaml", "/etc/crowdsec/profiles.yaml.bak",
	})

	// Write new profiles.yaml
	escapedContent := strings.ReplaceAll(string(newProfileBytes), "'", "'\\''")
	_, err = t.dockerClient.ExecCommand(t.cfg.CrowdsecContainerName, []string{
		"sh", "-c", fmt.Sprintf("echo '%s' > /etc/crowdsec/profiles.yaml", escapedContent),
	})
	if err != nil {
		// Restore backup if failed
		_, _ = t.dockerClient.ExecCommand(t.cfg.CrowdsecContainerName, []string{
			"mv", "/etc/crowdsec/profiles.yaml.bak", "/etc/crowdsec/profiles.yaml",
		})
		return fmt.Errorf("failed to write profiles.yaml: %w", err)
	}

	// Reload profiles
	_, _ = t.dockerClient.ExecCommand(t.cfg.CrowdsecContainerName, []string{
		"cscli", "profiles", "reload",
	})

	logger.Info("CrowdSec profiles updated successfully")
	return nil
}