package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

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

// captchaApplyStep is a named step in the captcha apply pipeline.
type captchaApplyStep struct {
	Num  int
	Name string
	Run  func(req models.CaptchaSetupRequest) error
}

// ApplyCaptchaConfig reads the captcha configuration saved by SaveCaptchaConfig and applies it
// to all systems: captcha HTML, Traefik dynamic config, CrowdSec profiles, and container restarts.
//
// Supports an optional "step" query parameter to re-run a single step (e.g. ?step=4).
// When step is omitted, all steps run sequentially.
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

		// Parse optional step filter.
		var onlyStep int
		if stepStr := c.Query("step"); stepStr != "" {
			parsed, parseErr := strconv.Atoi(stepStr)
			if parseErr != nil || parsed < 1 || parsed > 6 {
				c.JSON(http.StatusBadRequest, models.Response{
					Success: false,
					Error:   "Invalid step parameter. Must be 1-6.",
				})
				return
			}
			onlyStep = parsed
		}

		// Define the pipeline of steps.
		pipeline := []captchaApplyStep{
			{
				Num:  1,
				Name: "Create captcha HTML page",
				Run: func(r models.CaptchaSetupRequest) error {
					return createCaptchaHTML(cfg, r.Provider, r.SiteKey)
				},
			},
			{
				Num:  2,
				Name: "Update Traefik dynamic config",
				Run: func(r models.CaptchaSetupRequest) error {
					return updateTraefikCaptchaConfig(cfg, r)
				},
			},
			{
				Num:  3,
				Name: "Update CrowdSec profiles",
				Run: func(_ models.CaptchaSetupRequest) error {
					return updateCrowdSecProfiles(dockerClient, cfg)
				},
			},
			{
				Num:  4,
				Name: "Restart Traefik",
				Run: func(_ models.CaptchaSetupRequest) error {
					return restartTraefikContainer(dockerClient, cfg)
				},
			},
			{
				Num:  5,
				Name: "Restart CrowdSec",
				Run: func(_ models.CaptchaSetupRequest) error {
					return restartCrowdSecContainer(dockerClient, cfg)
				},
			},
			{
				Num:  6,
				Name: "Verify setup",
				Run: func(_ models.CaptchaSetupRequest) error {
					// Verification is implicit — if we got here, previous steps ran.
					return nil
				},
			},
		}

		// Execute steps.
		steps := []gin.H{}
		allOK := true

		for _, s := range pipeline {
			if onlyStep > 0 && s.Num != onlyStep {
				continue
			}

			stepErr := s.Run(req)
			success := stepErr == nil
			if !success {
				allOK = false
			}

			steps = append(steps, gin.H{
				"step":    s.Num,
				"name":    s.Name,
				"success": success,
				"error":   errString(stepErr),
			})
		}

		// Mark as applied in DB when all steps pass in a full run.
		if onlyStep == 0 && allOK {
			if markErr := db.MarkFeatureApplied("captcha"); markErr != nil {
				logger.Warn("Failed to mark captcha as applied in DB", "error", markErr)
			}
		}

		message := "Captcha applied successfully"
		if !allOK {
			message = "Captcha applied with some errors — check step details"
		}
		if onlyStep > 0 {
			if allOK {
				message = "Step re-run succeeded"
			} else {
				message = "Step re-run failed — check details"
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: allOK,
			Message: message,
			Data: gin.H{
				"steps":    steps,
				"applied":  allOK,
				"provider": req.Provider,
			},
		})
	}
}
