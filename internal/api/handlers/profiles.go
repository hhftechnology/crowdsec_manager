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

	"github.com/gin-gonic/gin"
)

// DefaultProfilesYAML is the default content for profiles.yaml
const DefaultProfilesYAML = `name: captcha_remediation
filters:
  - Alert.Remediation == true && Alert.GetScope() == "Ip" && Alert.GetScenario() contains "http"
decisions:
  - type: captcha
    duration: 4h
on_success: break

---
name: default_ip_remediation
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
 - type: ban
   duration: 4h
on_success: break

---
name: default_range_remediation
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Range"
decisions:
 - type: ban
   duration: 4h
on_success: break
`

func getProfilesPath(cfg *config.Config) string {
	// Assume profiles.yaml is in the same directory as acquis.yaml
	return filepath.Join(filepath.Dir(cfg.CrowdSecAcquisFile), "profiles.yaml")
}

// createDefaultProfilesYaml creates a default profiles.yaml file
func createDefaultProfilesYaml(path string) error {
	// Ensure the directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	// Write default content
	if err := os.WriteFile(path, []byte(DefaultProfilesYAML), 0644); err != nil {
		return fmt.Errorf("failed to write default profiles.yaml: %v", err)
	}

	logger.Info("Created default profiles.yaml", "path", path)
	return nil
}

// GetProfiles reads the content of profiles.yaml
// If the file doesn't exist, it creates a default one
func GetProfiles(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		profilesPath := getProfilesPath(cfg)
		content, err := os.ReadFile(profilesPath)
		if err != nil {
			if os.IsNotExist(err) {
				// Create default profiles.yaml if it doesn't exist
				logger.Info("profiles.yaml not found, creating default", "path", profilesPath)
				if err := createDefaultProfilesYaml(profilesPath); err != nil {
					c.JSON(http.StatusInternalServerError, models.Response{
						Success: false,
						Error:   fmt.Sprintf("failed to create default profiles.yaml: %v", err),
					})
					return
				}
				// Read the newly created file
				content, err = os.ReadFile(profilesPath)
				if err != nil {
					c.JSON(http.StatusInternalServerError, models.Response{
						Success: false,
						Error:   fmt.Sprintf("failed to read profiles.yaml after creation: %v", err),
					})
					return
				}
			} else {
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("failed to read profiles.yaml: %v", err),
				})
				return
			}
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

		// Ensure directory exists
		dir := filepath.Dir(profilesPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("failed to create directory: %v", err),
			})
			return
		}

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

		logger.Info("Updated profiles.yaml", "path", profilesPath)

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
