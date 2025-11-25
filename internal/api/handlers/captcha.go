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

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

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

		// 1. Update CrowdSec profiles.yaml to add captcha remediation
		profilesContent := `name: default_ip_remediation
filters:
 - "Alert.Remediation == true && Alert.GetScope() == 'Ip'"
decisions:
 - type: ban
   duration: 4h
 - type: captcha
   duration: 4h
on_success: break
`
		// Backup existing profiles.yaml
		_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cp", "/etc/crowdsec/profiles.yaml", "/etc/crowdsec/profiles.yaml.bak",
		})

		_, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"sh", "-c", fmt.Sprintf("echo '%s' > /etc/crowdsec/profiles.yaml", profilesContent) + " && cscli profiles reload",
		})
		if err != nil {
			// Restore backup if failed
			_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
				"mv", "/etc/crowdsec/profiles.yaml.bak", "/etc/crowdsec/profiles.yaml",
			})
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update CrowdSec profiles: %v", err),
			})
			return
		}

		// 2. Configure Traefik bouncer for captcha
		// Read config
		configContent, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"cat", "/etc/traefik/dynamic_config.yml",
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to read Traefik config",
			})
			return
		}

		// Parse YAML
		var dynamicConfig map[string]interface{}
		if err := yaml.Unmarshal([]byte(configContent), &dynamicConfig); err != nil {
			logger.Error("Failed to parse Traefik dynamic config", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse Traefik config: %v", err),
			})
			return
		}

		// Ensure structure exists
		httpConf, ok := dynamicConfig["http"].(map[string]interface{})
		if !ok {
			httpConf = make(map[string]interface{})
			dynamicConfig["http"] = httpConf
		}

		middlewares, ok := httpConf["middlewares"].(map[string]interface{})
		if !ok {
			middlewares = make(map[string]interface{})
			httpConf["middlewares"] = middlewares
		}

		// Configure captcha middleware
		// We look for the crowdsec bouncer middleware
		bouncerMiddlewareName := "crowdsec-bouncer-traefik-plugin"
		
		// Check if it exists, if not create it (though usually it should exist)
		bouncerConfig, ok := middlewares[bouncerMiddlewareName].(map[string]interface{})
		if !ok {
			bouncerConfig = make(map[string]interface{})
			middlewares[bouncerMiddlewareName] = bouncerConfig
		}

		pluginConfig, ok := bouncerConfig["plugin"].(map[string]interface{})
		if !ok {
			pluginConfig = make(map[string]interface{})
			bouncerConfig["plugin"] = pluginConfig
		}

		crowdsecPlugin, ok := pluginConfig["crowdsec-bouncer-traefik-plugin"].(map[string]interface{})
		if !ok {
			crowdsecPlugin = make(map[string]interface{})
			pluginConfig["crowdsec-bouncer-traefik-plugin"] = crowdsecPlugin
		}

		// Set captcha config
		crowdsecPlugin["captcha"] = map[string]interface{}{
			"enabled":   true,
			"provider":  "turnstile",
			"siteKey":   req.SiteKey,
			"secretKey": req.SecretKey,
		}

		// Marshal back to YAML
		newConfigBytes, err := yaml.Marshal(dynamicConfig)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to marshal new config: %v", err),
			})
			return
		}

		// Backup existing dynamic_config.yml
		_, _ = dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"cp", "/etc/traefik/dynamic_config.yml", "/etc/traefik/dynamic_config.yml.bak",
		})

		// Write back
		_, err = dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"sh", "-c", fmt.Sprintf("echo '%s' > /etc/traefik/dynamic_config.yml", string(newConfigBytes)),
		})
		if err != nil {
			// Restore backup
			_, _ = dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
				"mv", "/etc/traefik/dynamic_config.yml.bak", "/etc/traefik/dynamic_config.yml",
			})
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update Traefik config: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Captcha configured successfully",
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
