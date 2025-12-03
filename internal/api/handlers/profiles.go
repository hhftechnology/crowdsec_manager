package handlers

import (
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
)

func getProfilesPath(cfg *config.Config) string {
	// Assume profiles.yaml is in the same directory as acquis.yaml
	return filepath.Join(filepath.Dir(cfg.CrowdSecAcquisFile), "profiles.yaml")
}

// GetProfiles reads the content of profiles.yaml
func GetProfiles(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		profilesPath := getProfilesPath(cfg)
		content, err := os.ReadFile(profilesPath)
		if err != nil {
			if os.IsNotExist(err) {
				c.JSON(http.StatusNotFound, models.Response{
					Success: false,
					Error:   "profiles.yaml not found",
				})
				return
			}
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("failed to read profiles.yaml: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    string(content),
		})
	}
}

// UpdateProfiles updates profiles.yaml and optionally restarts CrowdSec
func UpdateProfiles(db *database.Database, cfg *config.Config, dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.ProfileRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "invalid request body",
			})
			return
		}

		profilesPath := getProfilesPath(cfg)

		// Save history
		if err := db.CreateProfileHistory(req.Content); err != nil {
			// Log error but proceed with file update? Or fail?
			// For now, let's fail to ensure history is kept.
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("failed to save profile history: %v", err),
			})
			return
		}

		// Write to file
		if err := os.WriteFile(profilesPath, []byte(req.Content), 0644); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("failed to write profiles.yaml: %v", err),
			})
			return
		}

		// Restart CrowdSec if requested
		if req.Restart {
			if err := dockerClient.RestartContainer(cfg.CrowdsecContainerName); err != nil {
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: true, // File saved, but restart failed
					Message: "Profiles updated but failed to restart CrowdSec",
					Error:   fmt.Sprintf("failed to restart crowdsec: %v", err),
				})
				return
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Profiles updated successfully",
		})
	}
}
