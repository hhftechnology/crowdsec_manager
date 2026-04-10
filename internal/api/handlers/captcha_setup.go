package handlers

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/traefikconfig"

	"gopkg.in/yaml.v3"
)

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

// detectCaptchaInConfig checks if captcha is configured in the Traefik dynamic config and profiles.yaml
func detectCaptchaInConfig(configContent string) (enabled bool, provider string, hasHTMLPath bool) {
	configLower := strings.ToLower(configContent)

	if strings.Contains(configLower, "captchaprovider") || strings.Contains(configLower, "captchasitekey") {
		enabled = true

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

	if strings.Contains(configLower, "captchahtmlfilepath") {
		hasHTMLPath = true
	}

	return
}

// extractCaptchaKeys extracts site key and secret key from one or more YAML documents.
func extractCaptchaKeys(configContent string) (siteKey string, secretKey string) {
	decoder := yaml.NewDecoder(strings.NewReader(configContent))
	for {
		var config map[string]interface{}
		if err := decoder.Decode(&config); err != nil {
			break
		}

		if http, ok := config["http"].(map[string]interface{}); ok {
			if middlewares, ok := http["middlewares"].(map[string]interface{}); ok {
				for _, mw := range middlewares {
					if mwMap, ok := mw.(map[string]interface{}); ok {
						if plugin, ok := mwMap["plugin"].(map[string]interface{}); ok {
							for k, v := range plugin {
								if strings.Contains(strings.ToLower(k), "crowdsec") {
									if crowdsec, ok := v.(map[string]interface{}); ok {
										if key, ok := crowdsec["captchaSiteKey"].(string); ok {
											siteKey = key
										}
										if key, ok := crowdsec["captchaSecretKey"].(string); ok {
											secretKey = key
										}
										return siteKey, secretKey
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return siteKey, secretKey
}

// updateTraefikCaptchaConfig updates the CrowdSec-managed Traefik dynamic config path with captcha configuration.
func updateTraefikCaptchaConfig(cfg *config.Config, req models.CaptchaSetupRequest) error {
	dynamicConfigPath, err := traefikconfig.ManagedHostFilePath(cfg, cfg.TraefikDynamicConfig)
	if err != nil {
		return fmt.Errorf("failed to resolve Traefik dynamic config path: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(dynamicConfigPath), 0755); err != nil {
		return fmt.Errorf("failed to prepare Traefik dynamic config path: %v", err)
	}

	configBytes, err := os.ReadFile(dynamicConfigPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read Traefik dynamic config from local path: %v", err)
		}
		configBytes = []byte{}
	}

	var node yaml.Node
	if err := yaml.Unmarshal(configBytes, &node); err != nil {
		return fmt.Errorf("failed to parse Traefik dynamic config: %v", err)
	}

	if len(node.Content) == 0 {
		node.Kind = yaml.DocumentNode
		node.Content = []*yaml.Node{
			{Kind: yaml.MappingNode},
		}
	} else if node.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("Traefik dynamic config root is not a mapping")
	}
	rootMap := node.Content[0]

	findOrCreateMap := func(parent *yaml.Node, key string) *yaml.Node {
		for i := 0; i < len(parent.Content); i += 2 {
			if parent.Content[i].Value == key {
				if parent.Content[i+1].Kind != yaml.MappingNode {
					parent.Content[i+1] = &yaml.Node{Kind: yaml.MappingNode}
				}
				return parent.Content[i+1]
			}
		}
		keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
		valNode := &yaml.Node{Kind: yaml.MappingNode}
		parent.Content = append(parent.Content, keyNode, valNode)
		return valNode
	}

	httpNode := findOrCreateMap(rootMap, "http")
	middlewaresNode := findOrCreateMap(httpNode, "middlewares")

	var crowdsecPluginNode *yaml.Node

	possibleNames := []string{
		"crowdsec-bouncer-traefik-plugin",
		"crowdsec-bouncer",
		"crowdsec",
	}

	for i := 0; i < len(middlewaresNode.Content); i += 2 {
		mwBody := middlewaresNode.Content[i+1]

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

	if crowdsecPluginNode == nil {
		mwName := "crowdsec-bouncer-traefik-plugin"

		nameTaken := false
		for i := 0; i < len(middlewaresNode.Content); i += 2 {
			if middlewaresNode.Content[i].Value == mwName {
				nameTaken = true
				break
			}
		}

		if nameTaken {
			for _, name := range possibleNames {
				taken := false
				for i := 0; i < len(middlewaresNode.Content); i += 2 {
					if middlewaresNode.Content[i].Value == name {
						taken = true
						break
					}
				}
				if !taken {
					mwName = name
					break
				}
			}
		}

		middlewareNode := findOrCreateMap(middlewaresNode, mwName)
		pluginNode := findOrCreateMap(middlewareNode, "plugin")
		crowdsecPluginNode = findOrCreateMap(pluginNode, "crowdsec-bouncer-traefik-plugin")
	}

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

	provider := "turnstile"
	if req.Provider != "" {
		provider = req.Provider
	}

	setScalar(crowdsecPluginNode, "captchaProvider", provider, "")
	setScalar(crowdsecPluginNode, "captchaSiteKey", req.SiteKey, "")
	setScalar(crowdsecPluginNode, "captchaSecretKey", req.SecretKey, "")
	setScalar(crowdsecPluginNode, "captchaHTMLFilePath", cfg.TraefikCaptchaHTMLPath, "")
	setScalar(crowdsecPluginNode, "captchaGracePeriodSeconds", strconv.Itoa(cfg.CaptchaGracePeriod), "!!int")

	// Remove old nested "captcha" key if it exists
	for i := 0; i < len(crowdsecPluginNode.Content); i += 2 {
		if crowdsecPluginNode.Content[i].Value == "captcha" {
			crowdsecPluginNode.Content = append(crowdsecPluginNode.Content[:i], crowdsecPluginNode.Content[i+2:]...)
			break
		}
	}

	// Create backup before modifying
	backupPath := dynamicConfigPath + ".bak"
	if err := os.WriteFile(backupPath, configBytes, 0644); err != nil {
		logger.Warn("Failed to create backup of Traefik dynamic config", "error", err)
	}

	newConfigBytes, err := yaml.Marshal(&node)
	if err != nil {
		return fmt.Errorf("failed to marshal Traefik dynamic config: %v", err)
	}

	if err := os.WriteFile(dynamicConfigPath, newConfigBytes, 0644); err != nil {
		if backupBytes, err2 := os.ReadFile(backupPath); err2 == nil {
			os.WriteFile(dynamicConfigPath, backupBytes, 0644)
		}
		return fmt.Errorf("failed to write Traefik dynamic config to local path: %v", err)
	}

	logger.Info("Traefik dynamic config updated successfully on local filesystem", "path", dynamicConfigPath)
	return nil
}
