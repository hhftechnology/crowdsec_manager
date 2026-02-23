package handlers

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// SetupCaptcha sets up Cloudflare Turnstile captcha
func SetupCaptcha(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
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

		// Use local path for Traefik config directory (mapped via /app/config)
		traefikConfigDir := filepath.Join(cfg.ConfigDir, "traefik")

		// Verify the directory exists
		if _, err := os.Stat(traefikConfigDir); err != nil {
			logger.Error("Traefik config directory not found", "path", traefikConfigDir, "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Traefik configuration directory not found",
			})
			return
		}

		// Create conf directory if it doesn't exist
		confDir := filepath.Join(traefikConfigDir, "conf")
		if err := os.MkdirAll(confDir, 0755); err != nil {
			logger.Error("Failed to create conf directory", "error", err, "path", confDir)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to create conf directory: %v", err),
			})
			return
		}
		logger.Info("Ensured conf directory exists", "path", confDir)

		// Write captcha.html to conf directory
		captchaHTMLPath := filepath.Join(confDir, "captcha.html")
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
		time.Sleep(3 * time.Second)

		// STEP 5: Restart CrowdSec container
		logger.Info("Restarting CrowdSec container")
		if err := dockerClient.RestartContainer(cfg.CrowdsecContainerName); err != nil {
			logger.Warn("Failed to restart CrowdSec", "error", err)
		} else {
			logger.Info("CrowdSec restarted successfully")
			time.Sleep(3 * time.Second)
		}

		// STEP 6: Verify setup
		logger.Info("Verifying captcha setup")
		verified := verifyCaptchaSetup(dockerClient, cfg)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Captcha configured successfully",
			Data: gin.H{
				"captcha_html_created":   true,
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
		dockerClient = resolveDockerClient(c, dockerClient)
		logger.Info("Getting captcha status")

		// Check if captcha.env exists (saved configuration)
		output, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"cat", cfg.TraefikCaptchaEnvPath,
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
		dynamicConfigPath := cfg.TraefikDynamicConfig
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
		siteKey := ""
		secretKey := ""

		if err == nil && configContent != "" {
			configured, detectedProvider, hasHTMLPath = detectCaptchaInConfig(configContent)
			siteKey, secretKey = extractCaptchaKeys(configContent)
		}

		// Check if captcha.html exists on local filesystem (via /app/config mount)
		captchaHTMLExistsOnHost := false
		hostHTMLPath := ""

		localConfPath := filepath.Join(cfg.ConfigDir, "traefik", "conf")
		hostHTMLPath = filepath.Join(localConfPath, "captcha.html")

		if _, err := os.Stat(hostHTMLPath); err == nil {
			captchaHTMLExistsOnHost = true
		}

		// Check if captcha.html exists in Traefik container (verifies mount is working)
		captchaHTMLExistsInContainer := false
		exists, err := dockerClient.FileExists(cfg.TraefikContainerName, cfg.TraefikCaptchaHTMLPath)
		if err == nil && exists {
			captchaHTMLExistsInContainer = true
		}

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
			"configured":                   configured,
			"configSaved":                  configSaved,
			"provider":                     finalProvider,
			"detectedProvider":             detectedProvider,
			"savedProvider":                savedProvider,
			"captchaHTMLExists":            captchaHTMLExists,
			"captchaHTMLExistsOnHost":      captchaHTMLExistsOnHost,
			"captchaHTMLExistsInContainer": captchaHTMLExistsInContainer,
			"hostHTMLPath":                 hostHTMLPath,
			"hasHTMLPath":                  hasHTMLPath,
			"implemented":                  configured && captchaHTMLExists,
			"site_key":                     siteKey,
			"secret_key":                   secretKey,
			"manually_configured":          configured && siteKey != "",
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    status,
		})
	}
}
