package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// createCaptchaHTML writes the captcha.html file to the host filesystem under cfg.ConfigDir.
// It returns the absolute path of the written file, or an error.
func createCaptchaHTML(cfg *config.Config, provider, siteKey string) error {
	captchaHTML := strings.ReplaceAll(captchaHTMLTemplate, "{{.SiteKey}}", siteKey)
	captchaHTML = strings.ReplaceAll(captchaHTML, "{{.RedirectURL}}", "")
	captchaHTML = strings.ReplaceAll(captchaHTML, "{{.CaptchaValue}}", "")

	traefikConfigDir := filepath.Join(cfg.ConfigDir, "traefik")
	if _, err := os.Stat(traefikConfigDir); err != nil {
		return fmt.Errorf("traefik configuration directory not found: %w", err)
	}

	confDir := filepath.Join(traefikConfigDir, "conf")
	if err := os.MkdirAll(confDir, 0755); err != nil {
		return fmt.Errorf("failed to create conf directory: %w", err)
	}

	captchaHTMLPath := filepath.Join(confDir, "captcha.html")
	if err := os.WriteFile(captchaHTMLPath, []byte(captchaHTML), 0644); err != nil {
		return fmt.Errorf("failed to write captcha.html: %w", err)
	}

	logger.Info("Captcha HTML file created", "path", captchaHTMLPath, "provider", provider)
	return nil
}

// restartTraefikContainer restarts the Traefik container with a short timeout
// to avoid exceeding the HTTP write deadline.
func restartTraefikContainer(dockerClient *docker.Client, cfg *config.Config) error {
	if err := dockerClient.RestartContainerWithTimeout(cfg.TraefikContainerName, 10); err != nil {
		return fmt.Errorf("failed to restart Traefik: %w", err)
	}
	return nil
}

// restartCrowdSecContainer restarts the CrowdSec container with a short timeout.
func restartCrowdSecContainer(dockerClient *docker.Client, cfg *config.Config) error {
	if err := dockerClient.RestartContainerWithTimeout(cfg.CrowdsecContainerName, 10); err != nil {
		return fmt.Errorf("failed to restart CrowdSec: %w", err)
	}
	return nil
}

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
		if err := createCaptchaHTML(cfg, req.Provider, req.SiteKey); err != nil {
			logger.Error("Failed to create captcha.html", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to create captcha.html: %v", err),
			})
			return
		}
		captchaHTMLPath := filepath.Join(cfg.ConfigDir, "traefik", "conf", "captcha.html")

		// STEP 2: Update Traefik dynamic_config.yml
		logger.Info("Updating Traefik dynamic configuration")
		traefikConfigDir := filepath.Join(cfg.ConfigDir, "traefik")
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
		logger.Info("Restarting Traefik container")
		if err := restartTraefikContainer(dockerClient, cfg); err != nil {
			logger.Error("Failed to restart Traefik", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to restart Traefik after configuration update: %v", err),
			})
			return
		}
		logger.Info("Traefik restarted successfully")

		// STEP 5: Restart CrowdSec container
		logger.Info("Restarting CrowdSec container")
		if err := restartCrowdSecContainer(dockerClient, cfg); err != nil {
			logger.Warn("Failed to restart CrowdSec", "error", err)
		} else {
			logger.Info("CrowdSec restarted successfully")
		}

		// STEP 6: Verify setup
		logger.Info("Verifying captcha setup")
		verified := verifyCaptchaSetup(dockerClient, cfg)

		autoSnapshot("dynamic_config")
		autoSnapshot("acquis")

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Captcha configured successfully",
			Data: gin.H{
				"captcha_html_created":    true,
				"traefik_config_updated":  true,
				"crowdsec_config_updated": true,
				"traefik_restarted":       true,
				"crowdsec_restarted":      true,
				"verified":                verified,
				"captcha_html_path":       captchaHTMLPath,
			},
		})
	}
}

// GetCaptchaStatus retrieves the current captcha configuration status
func GetCaptchaStatus(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		logger.Info("Getting captcha status")

		// Primary source: feature_configs database table
		// SaveCaptchaConfig writes here, ApplyCaptchaConfig sets applied = true
		configSaved := false
		configured := false
		savedProvider := ""
		siteKey := ""
		secretKey := ""

		if db != nil {
			if featureCfg, err := db.GetFeatureConfig("captcha"); err == nil && featureCfg != nil {
				configSaved = true
				configured = featureCfg.Applied

				var req models.CaptchaSetupRequest
				if err := json.Unmarshal([]byte(featureCfg.ConfigJSON), &req); err != nil {
					logger.Warn("Failed to unmarshal captcha config from DB", "error", err)
				} else {
					savedProvider = req.Provider
					siteKey = req.SiteKey
					secretKey = req.SecretKey
				}
			}
		}

		// Supplementary: check dynamic_config.yml in Traefik container for live state
		dynamicConfigPath := cfg.TraefikDynamicConfig
		if db != nil {
			if path, err := db.GetTraefikDynamicConfigPath(); err == nil {
				dynamicConfigPath = path
			}
		}

		configContent, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"cat", dynamicConfigPath,
		})

		detectedProvider := ""
		hasHTMLPath := false

		if err == nil && configContent != "" {
			var liveConfigured bool
			liveConfigured, detectedProvider, hasHTMLPath = detectCaptchaInConfig(configContent)
			liveSiteKey, liveSecretKey := extractCaptchaKeys(configContent)
			// Use live container values if DB had no data
			if !configSaved && liveConfigured {
				configured = true
				siteKey = liveSiteKey
				secretKey = liveSecretKey
			}
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
