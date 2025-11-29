package handlers

import (
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/goccy/go-yaml"
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

// SetupCaptcha sets up Cloudflare Turnstile captcha
func SetupCaptcha(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.CaptchaSetupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		// Validate inputs
		if req.SiteKey == "" || req.SecretKey == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Site Key and Secret Key are required",
			})
			return
		}

		logger.Info("Setting up captcha", "site_key", req.SiteKey)

		// STEP 1: Create captcha.html file on host
		logger.Info("Creating captcha.html file")
		captchaHTML := strings.ReplaceAll(captchaHTMLTemplate, "{{.SiteKey}}", req.SiteKey)
		captchaHTML = strings.ReplaceAll(captchaHTML, "{{.RedirectURL}}", "")
		captchaHTML = strings.ReplaceAll(captchaHTML, "{{.CaptchaValue}}", "")

		// Get host path for Traefik config directory
		hostTraefikPath, found, err := dockerClient.GetHostMountPath(cfg.TraefikContainerName, "/etc/traefik")
		if err != nil || !found {
			logger.Error("Failed to get Traefik config path", "error", err, "found", found)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to locate Traefik configuration directory",
			})
			return
		}

		captchaHTMLPath := filepath.Join(hostTraefikPath, "captcha.html")
		if err := os.WriteFile(captchaHTMLPath, []byte(captchaHTML), 0644); err != nil {
			logger.Error("Failed to write captcha.html", "error", err, "path", captchaHTMLPath)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to create captcha.html: %v", err),
			})
			return
		}
		logger.Info("Captcha HTML file created", "path", captchaHTMLPath)

		// STEP 2: Update Traefik dynamic_config.yml
		logger.Info("Updating Traefik dynamic configuration")
		if err := updateTraefikCaptchaConfig(dockerClient, cfg, req); err != nil {
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

		// STEP 4: Restart Traefik container
		logger.Info("Restarting Traefik container")
		if err := dockerClient.RestartContainer(cfg.TraefikContainerName); err != nil {
			logger.Warn("Failed to restart Traefik", "error", err)
			// Don't fail the request, just warn
		} else {
			logger.Info("Traefik restarted successfully")
			// Wait for Traefik to be ready
			time.Sleep(2 * time.Second)
		}

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
func GetCaptchaStatus(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting captcha status")

		// Check if captcha.env exists (saved configuration)
		output, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"cat", "/etc/traefik/captcha.env",
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

		// Get dynamic config path from database
		dynamicConfigPath := "/etc/traefik/dynamic_config.yml"
		if db != nil {
			if path, err := db.GetTraefikDynamicConfigPath(); err == nil {
				dynamicConfigPath = path
			}
		}

		// Check dynamic_config.yml for actual captcha configuration
		configContent, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"cat", dynamicConfigPath,
		})

		configured := false
		detectedProvider := ""
		hasHTMLPath := false

		if err == nil && configContent != "" {
			configured, detectedProvider, hasHTMLPath = detectCaptchaInConfig(configContent)
		}

		// Check if captcha.html exists on host filesystem
		captchaHTMLExistsOnHost := false
		hostHTMLPath := ""
		hostConfPath, found, hostErr := dockerClient.GetHostMountPath(cfg.TraefikContainerName, "/etc/traefik/conf")
		if hostErr == nil && !found {
			// Try /etc/traefik and append /conf
			hostTraefikPath, found, err := dockerClient.GetHostMountPath(cfg.TraefikContainerName, "/etc/traefik")
			if err == nil && found {
				hostConfPath = filepath.Join(hostTraefikPath, "conf")
			}
		}
		if hostConfPath != "" {
			hostHTMLPath = filepath.Join(hostConfPath, "captcha.html")
			if _, err := os.Stat(hostHTMLPath); err == nil {
				captchaHTMLExistsOnHost = true
			}
		}

		// Check if captcha.html exists in Traefik container (verifies mount is working)
		captchaHTMLExistsInContainer := false
		exists, err := dockerClient.FileExists(cfg.TraefikContainerName, "/etc/traefik/conf/captcha.html")
		if err == nil && exists {
			captchaHTMLExistsInContainer = true
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
			"hasHTMLPath":                  hasHTMLPath,                     // True if captchaHTMLFilePath is configured
			"implemented":                  configured && captchaHTMLExists, // Fully implemented if both exist
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

	// Check if captcha is enabled in Traefik config
	if strings.Contains(configLower, "captcha:") && strings.Contains(configLower, "enabled: true") {
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

	// Check for HTML path (custom template)
	if strings.Contains(configLower, "htmlpath:") {
		hasHTMLPath = true
	}

	return
}

// updateTraefikCaptchaConfig updates Traefik's dynamic_config.yml with captcha configuration
func updateTraefikCaptchaConfig(dockerClient *docker.Client, cfg *config.Config, req models.CaptchaSetupRequest) error {
	// Get host path for Traefik config
	hostTraefikPath, found, err := dockerClient.GetHostMountPath(cfg.TraefikContainerName, "/etc/traefik")
	if err != nil || !found {
		return fmt.Errorf("failed to get Traefik config path: %v", err)
	}

	dynamicConfigPath := filepath.Join(hostTraefikPath, "dynamic_config.yml")

	// Read existing config
	configBytes, err := os.ReadFile(dynamicConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read dynamic_config.yml: %v", err)
	}

	// Parse YAML
	var dynamicConfig map[string]interface{}
	if err := yaml.Unmarshal(configBytes, &dynamicConfig); err != nil {
		return fmt.Errorf("failed to parse dynamic_config.yml: %v", err)
	}

	// Ensure http.middlewares structure exists
	if dynamicConfig["http"] == nil {
		dynamicConfig["http"] = make(map[string]interface{})
	}
	httpConf := dynamicConfig["http"].(map[string]interface{})

	if httpConf["middlewares"] == nil {
		httpConf["middlewares"] = make(map[string]interface{})
	}
	middlewares := httpConf["middlewares"].(map[string]interface{})

	// Find or create crowdsec bouncer middleware
	var crowdsecPlugin map[string]interface{}
	found = false

	// Try different possible middleware names
	possibleNames := []string{
		"crowdsec-bouncer-traefik-plugin",
		"crowdsec-bouncer",
		"crowdsec",
	}

	for _, name := range possibleNames {
		if mw, ok := middlewares[name].(map[string]interface{}); ok {
			if plugin, ok := mw["plugin"].(map[string]interface{}); ok {
				for pluginName, pluginCfg := range plugin {
					if strings.Contains(strings.ToLower(pluginName), "crowdsec") {
						if cfg, ok := pluginCfg.(map[string]interface{}); ok {
							crowdsecPlugin = cfg
							found = true
							break
						}
					}
				}
			}
		}
		if found {
			break
		}
	}

	// If not found, create new middleware
	if !found {
		middlewareName := "crowdsec-bouncer-traefik-plugin"
		middlewares[middlewareName] = map[string]interface{}{
			"plugin": map[string]interface{}{
				"crowdsec-bouncer-traefik-plugin": map[string]interface{}{},
			},
		}
		mw := middlewares[middlewareName].(map[string]interface{})
		plugin := mw["plugin"].(map[string]interface{})
		crowdsecPlugin = plugin["crowdsec-bouncer-traefik-plugin"].(map[string]interface{})
	}

	// Update captcha configuration
	crowdsecPlugin["captcha"] = map[string]interface{}{
		"enabled":         true,
		"provider":        "turnstile",
		"siteKey":         req.SiteKey,
		"secretKey":       req.SecretKey,
		"htmlPath":        "/etc/traefik/captcha.html",
		"gracePeriod":     "1800s",
		"captchaDuration": "14400s",
	}

	// Backup existing file
	backupPath := dynamicConfigPath + ".bak"
	if err := os.WriteFile(backupPath, configBytes, 0644); err != nil {
		logger.Warn("Failed to create backup of dynamic_config.yml", "error", err)
	}

	// Marshal back to YAML
	newConfigBytes, err := yaml.Marshal(dynamicConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal dynamic_config.yml: %v", err)
	}

	// Write updated config
	if err := os.WriteFile(dynamicConfigPath, newConfigBytes, 0644); err != nil {
		// Restore backup if write fails
		if backupBytes, err2 := os.ReadFile(backupPath); err2 == nil {
			os.WriteFile(dynamicConfigPath, backupBytes, 0644)
		}
		return fmt.Errorf("failed to write dynamic_config.yml: %v", err)
	}

	logger.Info("Traefik dynamic config updated successfully")
	return nil
}

// updateCrowdSecProfiles updates CrowdSec profiles.yaml to include captcha remediation
func updateCrowdSecProfiles(dockerClient *docker.Client, cfg *config.Config) error {
	// Read current profiles.yaml
	output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"cat", "/etc/crowdsec/profiles.yaml",
	})
	if err != nil {
		return fmt.Errorf("failed to read profiles.yaml: %v", err)
	}

	// Parse existing profiles
	var profiles []map[string]interface{}
	if err := yaml.Unmarshal([]byte(output), &profiles); err != nil {
		// If parsing fails, use default profile
		profiles = []map[string]interface{}{}
	}

	// Find or create default_ip_remediation profile
	defaultProfile := map[string]interface{}{
		"name": "default_ip_remediation",
		"filters": []string{
			"Alert.Remediation == true && Alert.GetScope() == 'Ip'",
		},
		"decisions": []map[string]interface{}{
			{
				"type":     "ban",
				"duration": "4h",
			},
			{
				"type":     "captcha",
				"duration": "4h",
			},
		},
		"on_success": "break",
	}

	// Check if profile already exists
	profileExists := false
	for i, profile := range profiles {
		if name, ok := profile["name"].(string); ok && name == "default_ip_remediation" {
			profiles[i] = defaultProfile
			profileExists = true
			break
		}
	}

	if !profileExists {
		profiles = append(profiles, defaultProfile)
	}

	// Marshal to YAML
	newProfileBytes, err := yaml.Marshal(profiles)
	if err != nil {
		return fmt.Errorf("failed to marshal profiles: %v", err)
	}

	// Backup existing profiles.yaml
	_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"cp", "/etc/crowdsec/profiles.yaml", "/etc/crowdsec/profiles.yaml.bak",
	})

	// Write new profiles.yaml
	escapedContent := strings.ReplaceAll(string(newProfileBytes), "'", "'\\''")
	_, err = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"sh", "-c", fmt.Sprintf("echo '%s' > /etc/crowdsec/profiles.yaml", escapedContent),
	})
	if err != nil {
		// Restore backup if failed
		_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"mv", "/etc/crowdsec/profiles.yaml.bak", "/etc/crowdsec/profiles.yaml",
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
	exists, err := dockerClient.FileExists(cfg.TraefikContainerName, "/etc/traefik/captcha.html")
	if err != nil || !exists {
		logger.Warn("Captcha HTML verification failed", "exists", exists, "error", err)
		return false
	}

	// Check 2: Dynamic config contains captcha settings
	configContent, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
		"cat", "/etc/traefik/dynamic_config.yml",
	})
	if err != nil {
		logger.Warn("Failed to read dynamic config for verification", "error", err)
		return false
	}

	if !strings.Contains(strings.ToLower(configContent), "captcha") {
		logger.Warn("Captcha not found in dynamic config")
		return false
	}

	// Check 3: CrowdSec profiles contain captcha decision
	profilesContent, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"cat", "/etc/crowdsec/profiles.yaml",
	})
	if err != nil {
		logger.Warn("Failed to read profiles for verification", "error", err)
		return false
	}

	if !strings.Contains(strings.ToLower(profilesContent), "captcha") {
		logger.Warn("Captcha not found in CrowdSec profiles")
		return false
	}

	logger.Info("Captcha setup verification passed")
	return true
}
