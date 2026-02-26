package handlers

import (
	"encoding/json"
	"net/http"
	"path/filepath"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// SaveCaptchaConfig persists captcha configuration to the database without applying it.
// This allows users to review the configuration before it is written to config files.
func SaveCaptchaConfig(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.CaptchaSetupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		if req.SiteKey == "" || req.SecretKey == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "site_key and secret_key are required",
			})
			return
		}

		configJSON, err := json.Marshal(req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to serialize config: " + err.Error(),
			})
			return
		}

		if err := db.SaveFeatureConfig("captcha", string(configJSON), "user"); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to save config to database: " + err.Error(),
			})
			return
		}

		logger.Info("Captcha config saved to database", "provider", req.Provider)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Captcha configuration saved. Use POST /api/captcha/apply to apply it.",
			Data: gin.H{
				"provider": req.Provider,
				"saved":    true,
				"next_steps": []string{
					"Review the configuration",
					"Click Apply to write config files and restart services",
				},
			},
		})
	}
}

// ApplyCaptchaConfig reads the captcha configuration saved by SaveCaptchaConfig and applies it
// to all systems: captcha HTML, Traefik dynamic config, CrowdSec profiles, and container restarts.
func ApplyCaptchaConfig(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		// Load config from DB.
		featureCfg, err := db.GetFeatureConfig("captcha")
		if err != nil || featureCfg == nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "No captcha configuration found. Save config first via POST /api/captcha/config",
			})
			return
		}

		var req models.CaptchaSetupRequest
		if err := json.Unmarshal([]byte(featureCfg.ConfigJSON), &req); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to parse saved config: " + err.Error(),
			})
			return
		}

		steps := []gin.H{}

		// Step 1: Write captcha.html to host filesystem.
		htmlErr := createCaptchaHTML(cfg, req.Provider, req.SiteKey)
		steps = append(steps, gin.H{
			"step":    1,
			"name":    "Create captcha HTML page",
			"success": htmlErr == nil,
			"error":   errString(htmlErr),
		})

		// Step 2: Update Traefik dynamic_config.yml.
		traefikConfigDir := filepath.Join(cfg.ConfigDir, "traefik")
		traefikErr := updateTraefikCaptchaConfig(dockerClient, cfg, req, traefikConfigDir)
		steps = append(steps, gin.H{
			"step":    2,
			"name":    "Update Traefik dynamic config",
			"success": traefikErr == nil,
			"error":   errString(traefikErr),
		})

		// Step 3: Update CrowdSec profiles.yaml.
		profilesErr := updateCrowdSecProfiles(dockerClient, cfg)
		steps = append(steps, gin.H{
			"step":    3,
			"name":    "Update CrowdSec profiles",
			"success": profilesErr == nil,
			"error":   errString(profilesErr),
		})

		// Step 4: Restart Traefik (stop + start for clean config reload).
		traefikRestartErr := restartTraefikContainer(dockerClient, cfg)
		steps = append(steps, gin.H{
			"step":    4,
			"name":    "Restart Traefik",
			"success": traefikRestartErr == nil,
			"error":   errString(traefikRestartErr),
		})

		// Step 5: Restart CrowdSec.
		csRestartErr := restartCrowdSecContainer(dockerClient, cfg)
		steps = append(steps, gin.H{
			"step":    5,
			"name":    "Restart CrowdSec",
			"success": csRestartErr == nil,
			"error":   errString(csRestartErr),
		})

		// Step 6: Verify the full setup.
		verified := htmlErr == nil && traefikErr == nil && profilesErr == nil
		steps = append(steps, gin.H{
			"step":    6,
			"name":    "Verify setup",
			"success": verified,
		})

		// Mark as applied in DB when all critical steps (HTML + Traefik + profiles) passed.
		allCriticalOK := htmlErr == nil && traefikErr == nil && profilesErr == nil
		if allCriticalOK {
			if markErr := db.MarkFeatureApplied("captcha"); markErr != nil {
				logger.Warn("Failed to mark captcha as applied in DB", "error", markErr)
			}
		}

		message := "Captcha applied successfully"
		if !allCriticalOK {
			message = "Captcha applied with some errors — check step details"
		}

		c.JSON(http.StatusOK, models.Response{
			Success: allCriticalOK,
			Message: message,
			Data: gin.H{
				"steps":    steps,
				"applied":  allCriticalOK,
				"provider": req.Provider,
			},
		})
	}
}

// errString safely converts an error to a string, returning "" for nil.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
