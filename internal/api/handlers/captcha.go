package handlers

import (
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/proxy"
	"crowdsec-manager/internal/validation"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
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

// SetupCaptcha sets up captcha using the proxy adapter
func SetupCaptcha(dockerClient *docker.Client, cfg *config.Config, proxyAdapter proxy.ProxyAdapter) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.CaptchaSetupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		// Validate provider
		if req.Provider != "" {
			providerResult := validation.ValidateCaptchaProvider(req.Provider)
			if !providerResult.Valid {
				c.JSON(http.StatusBadRequest, models.Response{
					Success: false,
					Error:   providerResult.Message,
				})
				return
			}
			req.Provider = providerResult.Value // Use normalized value
		}

		// Validate required inputs
		siteKeyResult := validation.ValidateNonEmpty(req.SiteKey, "Site Key")
		if !siteKeyResult.Valid {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   siteKeyResult.Message,
			})
			return
		}

		secretKeyResult := validation.ValidateNonEmpty(req.SecretKey, "Secret Key")
		if !secretKeyResult.Valid {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   secretKeyResult.Message,
			})
			return
		}

		// Check for dangerous characters in keys (prevent injection)
		if !validation.IsSafeForShell(req.SiteKey) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Site Key contains invalid characters",
			})
			return
		}
		if !validation.IsSafeForShell(req.SecretKey) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Secret Key contains invalid characters",
			})
			return
		}

		logger.Info("Setting up captcha", "site_key", req.SiteKey, "provider", req.Provider)

		// STEP 1: Create captcha.html file on host
		logger.Info("Creating captcha.html file")
		captchaHTML := strings.ReplaceAll(captchaHTMLTemplate, "{{.SiteKey}}", req.SiteKey)
		captchaHTML = strings.ReplaceAll(captchaHTML, "{{.RedirectURL}}", "")
		captchaHTML = strings.ReplaceAll(captchaHTML, "{{.CaptchaValue}}", "")

		// Use local path for Traefik config directory (mapped via /app/config)
		traefikConfigDir := filepath.Join(cfg.ConfigDir, "traefik")

		// Verify the directory exists
		if _, err := os.Stat(traefikConfigDir); err != nil {
			logger.Error("Traefik config directory not found", "path", traefikConfigDir, "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Traefik configuration directory not found at %s", traefikConfigDir),
			})
			return
		}

		// Determine the subdirectory based on configured container path
		// Container path format: /etc/traefik/<subdir>/captcha.html
		// We need to extract <subdir> and create it on the host
		containerCaptchaPath := cfg.Paths.TraefikCaptchaHTML
		subDir := filepath.Dir(strings.TrimPrefix(containerCaptchaPath, "/etc/traefik/"))

		// Create subdirectory if it doesn't exist
		captchaDir := filepath.Join(traefikConfigDir, subDir)
		if err := os.MkdirAll(captchaDir, 0755); err != nil {
			logger.Error("Failed to create captcha directory", "error", err, "path", captchaDir, "container_path", containerCaptchaPath)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to create captcha directory %s: %v", captchaDir, err),
			})
			return
		}
		logger.Info("Ensured captcha directory exists", "host_path", captchaDir, "container_path", containerCaptchaPath)

		// Write captcha.html to the configured directory
		captchaHTMLPath := filepath.Join(captchaDir, "captcha.html")
		if err := os.WriteFile(captchaHTMLPath, []byte(captchaHTML), 0644); err != nil {
			logger.Error("Failed to write captcha.html", "error", err, "host_path", captchaHTMLPath, "container_path", containerCaptchaPath)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to create captcha.html at %s: %v", captchaHTMLPath, err),
			})
			return
		}
		logger.Info("Captcha HTML file created", "host_path", captchaHTMLPath, "container_path", containerCaptchaPath)

		// STEP 2: Update Traefik dynamic_config.yml
		logger.Info("Updating Traefik dynamic configuration")
		if err := updateTraefikCaptchaConfig(dockerClient, cfg, req, traefikConfigDir); err != nil {
			logger.Error("Failed to update Traefik config", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update Traefik configuration: %v", err),
			})
			return
		}

		// STEP 3: Update CrowdSec profiles.yaml
		logger.Info("Updating CrowdSec profiles")
		if err := updateCrowdSecProfiles(dockerClient, cfg); err != nil {
			logger.Error("Failed to update CrowdSec profiles", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update CrowdSec profiles: %v", err),
			})
			return
		}

		// STEP 4: Stop and Start Traefik container (for clean reload)
		logger.Info("Stopping Traefik container")
		if err := dockerClient.StopContainer(cfg.TraefikContainerName); err != nil {
			logger.Warn("Failed to stop Traefik", "error", err)
		} else {
			logger.Info("Traefik stopped successfully")
			// Wait a moment
			time.Sleep(1 * time.Second)
		}

		logger.Info("Starting Traefik container")
		if err := dockerClient.StartContainer(cfg.TraefikContainerName); err != nil {
			logger.Error("Failed to start Traefik", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to start Traefik after configuration update: %v", err),
			})
			return
		}
		logger.Info("Traefik started successfully")
		// Wait for Traefik to be fully ready
		time.Sleep(3 * time.Second)

		// STEP 5: Restart CrowdSec container
		logger.Info("Restarting CrowdSec container")
		if err := dockerClient.RestartContainer(cfg.CrowdsecContainerName); err != nil {
			logger.Warn("Failed to restart CrowdSec", "error", err)
			// Don't fail the request, just warn
		} else {
			logger.Info("CrowdSec restarted successfully")
			// Wait for CrowdSec to be ready
			time.Sleep(3 * time.Second)
		}

		// STEP 6: Verify setup
		logger.Info("Verifying captcha setup")
		verified := verifyCaptchaSetup(dockerClient, cfg)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Captcha configured successfully",
			Data: gin.H{
				"captcha_html_created":  true,
				"traefik_config_updated": true,
				"crowdsec_config_updated": true,
				"traefik_restarted":      true,
				"crowdsec_restarted":     true,
				"verified":               verified,
				"captcha_html_path":      captchaHTMLPath,
			},
		})
	}
}

// GetCaptchaStatus retrieves the current captcha configuration status
func GetCaptchaStatus(dockerClient *docker.Client, db *database.Database, cfg *config.Config, proxyAdapter proxy.ProxyAdapter) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting captcha status")

		// Check if captcha.env exists (saved configuration)
		captchaEnvPath := "/etc/traefik/captcha.env" // This is a Traefik container path
		logger.Info("Checking captcha environment file", "path", captchaEnvPath)
		output, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"cat", captchaEnvPath,
		})

		configSaved := false
		savedProvider := ""

		if err == nil && strings.TrimSpace(output) != "" {
			configSaved = true
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "CAPTCHA_PROVIDER=") {
					savedProvider = strings.TrimSpace(strings.TrimPrefix(line, "CAPTCHA_PROVIDER="))
					break
				}
			}
		}

		// Get dynamic config path from PathConfig (with database fallback for backward compatibility)
		dynamicConfigPath := cfg.Paths.TraefikDynamicConfig
		if db != nil {
			if path, err := db.GetTraefikDynamicConfigPath(); err == nil && path != "" {
				dynamicConfigPath = path
			}
		}
		logger.Info("Checking Traefik dynamic configuration", "path", dynamicConfigPath)

		// Check dynamic_config.yml for actual captcha configuration
		configContent, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"cat", dynamicConfigPath,
		})

		configured := false
		detectedProvider := ""
		hasHTMLPath := false
		siteKey := ""
		secretKey := ""

		if err == nil && configContent != "" {
			configured, detectedProvider, hasHTMLPath = detectCaptchaInConfig(configContent)

			// Extract site key and secret key from config
			siteKey, secretKey = extractCaptchaKeys(configContent)
		}

		// Check if captcha.html exists on local filesystem (via /app/config mount)
		captchaHTMLExistsOnHost := false
		hostHTMLPath := ""

		// Determine host path based on configured container path
		// Container path format: /etc/traefik/<subdir>/captcha.html
		containerCaptchaPath := cfg.Paths.TraefikCaptchaHTML
		subDir := filepath.Dir(strings.TrimPrefix(containerCaptchaPath, "/etc/traefik/"))
		traefikConfigDir := filepath.Join(cfg.ConfigDir, "traefik")
		localConfPath := filepath.Join(traefikConfigDir, subDir)
		hostHTMLPath = filepath.Join(localConfPath, "captcha.html")

		logger.Info("Checking captcha HTML file on host", "path", hostHTMLPath, "container_path", containerCaptchaPath)
		if _, err := os.Stat(hostHTMLPath); err == nil {
			captchaHTMLExistsOnHost = true
		} else {
			logger.Debug("Captcha HTML file not found on host", "path", hostHTMLPath, "error", err)
		}

		// Check if captcha.html exists in Traefik container (verifies mount is working)
		captchaHTMLExistsInContainer := false
		actualCaptchaPath := containerCaptchaPath // Track where we actually found it

		logger.Info("Checking captcha HTML file in container", "path", containerCaptchaPath)
		exists, err := dockerClient.FileExists(cfg.TraefikContainerName, containerCaptchaPath)
		if err == nil && exists {
			captchaHTMLExistsInContainer = true
		} else if err != nil {
			logger.Warn("Failed to check captcha HTML file in container", "path", containerCaptchaPath, "error", err)

			// Try common fallback locations if configured path doesn't exist
			fallbackPaths := []string{
				"/etc/traefik/captcha.html",
				"/etc/traefik/assets/captcha.html",
				"/etc/traefik/conf/captcha.html",
				"/captcha.html",
			}

			for _, fallbackPath := range fallbackPaths {
				if fallbackPath != containerCaptchaPath {
					logger.Debug("Trying fallback path", "path", fallbackPath)
					if exists, err := dockerClient.FileExists(cfg.TraefikContainerName, fallbackPath); err == nil && exists {
						captchaHTMLExistsInContainer = true
						actualCaptchaPath = fallbackPath
						logger.Info("Found captcha HTML at fallback location", "path", fallbackPath, "configured_path", containerCaptchaPath)
						break
					}
				}
			}
		}

		// For backwards compatibility, captchaHTMLExists is true if it exists in container
		captchaHTMLExists := captchaHTMLExistsInContainer

		// Determine final provider (prefer detected over saved)
		finalProvider := detectedProvider
		if finalProvider == "" {
			finalProvider = savedProvider
		}

		// Ensure all string fields are never nil (use empty string instead)
		if finalProvider == "" {
			finalProvider = ""
		}
		if detectedProvider == "" {
			detectedProvider = ""
		}
		if savedProvider == "" {
			savedProvider = ""
		}

		status := gin.H{
			"configured":                   configured,                      // True if captcha is in dynamic_config.yml
			"configSaved":                  configSaved,                     // True if captcha.env exists
			"provider":                     finalProvider,                   // Detected or saved provider
			"detectedProvider":             detectedProvider,                // Provider from dynamic_config.yml
			"savedProvider":                savedProvider,                   // Provider from captcha.env
			"captchaHTMLExists":            captchaHTMLExists,               // True if captcha.html exists in container
			"captchaHTMLExistsOnHost":      captchaHTMLExistsOnHost,         // True if captcha.html exists on host
			"captchaHTMLExistsInContainer": captchaHTMLExistsInContainer,    // True if captcha.html exists in container
			"hostHTMLPath":                 hostHTMLPath,                    // Host path where captcha.html should be
			"containerHTMLPath":            containerCaptchaPath,            // Configured container path
			"actualContainerHTMLPath":      actualCaptchaPath,               // Actual path where file was found (may differ from configured)
			"hasHTMLPath":                  hasHTMLPath,                     // True if captchaHTMLFilePath is configured
			"implemented":                  configured && captchaHTMLExists, // Fully implemented if both exist
			"site_key":                     siteKey,                         // Site key from config (for UI pre-population)
			"secret_key":                   secretKey,                       // Secret key from config (for UI pre-population)
			"manually_configured":          configured && siteKey != "",     // True if config was manually set
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    status,
		})
	}
}

// detectCaptchaInConfig checks if captcha is configured in dynamic_config.yml and profiles.yaml
func detectCaptchaInConfig(configContent string) (enabled bool, provider string, hasHTMLPath bool) {
	configLower := strings.ToLower(configContent)

	// Check if captcha keys exist (flat structure)
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

	// Check for HTML path
	if strings.Contains(configLower, "captchahtmlfilepath") {
		hasHTMLPath = true
	}

	return
}

// extractCaptchaKeys extracts site key and secret key from dynamic_config.yml content
func extractCaptchaKeys(configContent string) (siteKey string, secretKey string) {
	// Parse YAML to extract keys
	var config map[string]interface{}
	if err := yaml.Unmarshal([]byte(configContent), &config); err != nil {
		return "", ""
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
									// Extract keys from flat structure
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

	return siteKey, secretKey
}

// updateTraefikCaptchaConfig updates Traefik's dynamic_config.yml with captcha configuration
func updateTraefikCaptchaConfig(dockerClient *docker.Client, cfg *config.Config, req models.CaptchaSetupRequest, traefikConfigDir string) error {
	// Read existing config from local filesystem (via /app/config mount)
	dynamicConfigPath := filepath.Join(traefikConfigDir, "dynamic_config.yml")

	configBytes, err := os.ReadFile(dynamicConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read dynamic_config.yml from local path: %v", err)
	}

	// Parse YAML into Node to preserve comments
	var node yaml.Node
	if err := yaml.Unmarshal(configBytes, &node); err != nil {
		return fmt.Errorf("failed to parse dynamic_config.yml: %v", err)
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
					// If it exists but isn't a map, we have a problem. Overwrite?
					// For now, let's assume structure is correct or overwrite.
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
	// We look for any middleware that has the crowdsec plugin
	var crowdsecPluginNode *yaml.Node
	var middlewareNode *yaml.Node
	
	possibleNames := []string{
		"crowdsec-bouncer-traefik-plugin",
		"crowdsec-bouncer",
		"crowdsec",
	}

	// Search existing
	for i := 0; i < len(middlewaresNode.Content); i += 2 {
		mwBody := middlewaresNode.Content[i+1]
		
		// Check if this middleware has the plugin
		for j := 0; j < len(mwBody.Content); j += 2 {
			if mwBody.Content[j].Value == "plugin" {
				pluginBody := mwBody.Content[j+1]
				for k := 0; k < len(pluginBody.Content); k += 2 {
					if strings.Contains(strings.ToLower(pluginBody.Content[k].Value), "crowdsec") {
						middlewareNode = mwBody
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
		// Use default name
		mwName := "crowdsec-bouncer-traefik-plugin"
		
		// Check if name is taken (simple check)
		nameTaken := false
		for i := 0; i < len(middlewaresNode.Content); i += 2 {
			if middlewaresNode.Content[i].Value == mwName {
				nameTaken = true
				break
			}
		}
		
		if nameTaken {
			// Try alternatives
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

		middlewareNode = findOrCreateMap(middlewaresNode, mwName)
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
	
	// Use configured captcha HTML path from PathConfig
	captchaHTMLPath := cfg.Paths.TraefikCaptchaHTML
	logger.Info("Setting captcha HTML file path in config", "path", captchaHTMLPath)

	setScalar(crowdsecPluginNode, "captchaProvider", provider, "")
	setScalar(crowdsecPluginNode, "captchaSiteKey", req.SiteKey, "")
	setScalar(crowdsecPluginNode, "captchaSecretKey", req.SecretKey, "")
	setScalar(crowdsecPluginNode, "captchaHTMLFilePath", captchaHTMLPath, "")
	setScalar(crowdsecPluginNode, "captchaGracePeriodSeconds", "1800", "!!int")

	// Remove old nested "captcha" key if it exists
	for i := 0; i < len(crowdsecPluginNode.Content); i += 2 {
		if crowdsecPluginNode.Content[i].Value == "captcha" {
			// Remove key and value
			crowdsecPluginNode.Content = append(crowdsecPluginNode.Content[:i], crowdsecPluginNode.Content[i+2:]...)
			break
		}
	}

	// Create backup before modifying
	backupPath := dynamicConfigPath + ".bak"
	if err := os.WriteFile(backupPath, configBytes, 0644); err != nil {
		logger.Warn("Failed to create backup of dynamic_config.yml", "error", err)
	}

	// Marshal back to YAML
	newConfigBytes, err := yaml.Marshal(&node)
	if err != nil {
		return fmt.Errorf("failed to marshal dynamic_config.yml: %v", err)
	}

	// Write updated config to host filesystem
	if err := os.WriteFile(dynamicConfigPath, newConfigBytes, 0644); err != nil {
		// Restore backup if write fails
		if backupBytes, err2 := os.ReadFile(backupPath); err2 == nil {
			os.WriteFile(dynamicConfigPath, backupBytes, 0644)
		}
		return fmt.Errorf("failed to write dynamic_config.yml to local path: %v", err)
	}

	logger.Info("Traefik dynamic config updated successfully on local filesystem")
	return nil
}

// updateCrowdSecProfiles updates CrowdSec profiles.yaml to include captcha remediation
func updateCrowdSecProfiles(dockerClient *docker.Client, cfg *config.Config) error {
	// Read current profiles.yaml using configured path
	profilesPath := cfg.Paths.CrowdSecProfilesFile
	logger.Info("Reading CrowdSec profiles configuration", "path", profilesPath)
	output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"cat", profilesPath,
	})
	if err != nil {
		return fmt.Errorf("failed to read profiles.yaml from %s: %v", profilesPath, err)
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
			return fmt.Errorf("failed to marshal profiles.yaml document %d: %v", i, err)
		}
	}
	encoder.Close()

	// Clean up output
	newProfileBytes := buf.String()
	newProfileBytes = strings.TrimPrefix(newProfileBytes, "---\n")

	// Backup existing profiles.yaml
	backupPath := profilesPath + ".bak"
	logger.Info("Creating backup of profiles.yaml", "backup_path", backupPath)
	_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"cp", profilesPath, backupPath,
	})

	// Write new profiles.yaml
	// We need to be careful with echo and large/complex content.
	// Using a temporary file approach or writing via stdin would be safer if possible,
	// but ExecCommand doesn't easily support stdin.
	// We'll escape single quotes.
	logger.Info("Writing updated profiles configuration", "path", profilesPath)
	escapedContent := strings.ReplaceAll(string(newProfileBytes), "'", "'\\''")
	_, err = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"sh", "-c", fmt.Sprintf("echo '%s' > %s", escapedContent, profilesPath),
	})
	if err != nil {
		// Restore backup if failed
		logger.Error("Failed to write profiles.yaml, restoring backup", "path", profilesPath, "error", err)
		_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"mv", backupPath, profilesPath,
		})
		return fmt.Errorf("failed to write profiles.yaml to %s: %v", profilesPath, err)
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
	captchaHTMLPath := cfg.Paths.TraefikCaptchaHTML
	logger.Info("Verifying captcha HTML file in container", "path", captchaHTMLPath)
	exists, err := dockerClient.FileExists(cfg.TraefikContainerName, captchaHTMLPath)
	if err != nil || !exists {
		logger.Warn("Captcha HTML verification failed", "path", captchaHTMLPath, "exists", exists, "error", err)
		return false
	}
	logger.Info("Captcha HTML file verified", "path", captchaHTMLPath)

	// Check 2: Dynamic config contains captcha settings
	dynamicConfigPath := cfg.Paths.TraefikDynamicConfig
	logger.Info("Verifying captcha settings in dynamic config", "path", dynamicConfigPath)
	configContent, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
		"cat", dynamicConfigPath,
	})
	if err != nil {
		logger.Warn("Failed to read dynamic config for verification", "path", dynamicConfigPath, "error", err)
		return false
	}

	if !strings.Contains(strings.ToLower(configContent), "captcha") {
		logger.Warn("Captcha not found in dynamic config")
		return false
	}
	logger.Info("Dynamic config contains captcha settings")

	// Check 3: Dynamic config references correct captcha.html path
	if !strings.Contains(configContent, captchaHTMLPath) {
		logger.Warn("Dynamic config does not reference correct captcha.html path", "expected_path", captchaHTMLPath)
		return false
	}
	logger.Info("Dynamic config references correct captcha.html path", "path", captchaHTMLPath)

	// Check 4: CrowdSec profiles contain captcha decision
	profilesPath := cfg.Paths.CrowdSecProfilesFile
	logger.Info("Verifying captcha decision in CrowdSec profiles", "path", profilesPath)
	profilesContent, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"cat", profilesPath,
	})
	if err != nil {
		logger.Warn("Failed to read profiles for verification", "path", profilesPath, "error", err)
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
