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

// readProfilesFromContainer reads profiles.yaml from CrowdSec container
func readProfilesFromContainer(dockerClient *docker.Client, cfg *config.Config) (string, error) {
	// Try to read profiles.yaml from container
	output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
		"cat", "/etc/crowdsec/profiles.yaml",
	})
	if err != nil {
		return "", fmt.Errorf("profiles.yaml not found in container: %w", err)
	}

	content := strings.TrimSpace(output)
	if content == "" {
		return "", fmt.Errorf("profiles.yaml is empty in container")
	}

	logger.Info("Read profiles.yaml from container")
	return content, nil
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
// Priority: 1) Host file, 2) Container file, 3) Default template
// Query parameter ?default=true forces using default template
func GetProfiles(cfg *config.Config, dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		profilesPath := getProfilesPath(cfg)
		var content []byte
		var err error
		var source string

		// Check if user wants to force default template
		useDefault := c.Query("default") == "true"

		if useDefault {
			logger.Info("User requested default profiles.yaml template")
			content = []byte(DefaultProfilesYAML)
			source = "default_template"
		} else {
			// Step 1: Try to read from host path
			content, err = os.ReadFile(profilesPath)
			if err == nil {
				source = "host_file"
				logger.Info("Read profiles.yaml from host", "path", profilesPath)
			} else if os.IsNotExist(err) {
				// Step 2: Try to read from container
				logger.Info("profiles.yaml not found on host, checking container")
				containerContent, containerErr := readProfilesFromContainer(dockerClient, cfg)
				if containerErr == nil {
					content = []byte(containerContent)
					source = "container"
					logger.Info("Read profiles.yaml from container, saving to host")

					// Save container content to host for future use
					dir := filepath.Dir(profilesPath)
					if err := os.MkdirAll(dir, 0755); err != nil {
						logger.Warn("Failed to create directory for profiles.yaml", "error", err)
					} else if err := os.WriteFile(profilesPath, content, 0644); err != nil {
						logger.Warn("Failed to save profiles.yaml to host", "error", err)
					} else {
						logger.Info("Saved profiles.yaml to host", "path", profilesPath)
					}
				} else {
					// Step 3: Use default template
					logger.Info("profiles.yaml not found in container, using default template")
					content = []byte(DefaultProfilesYAML)
					source = "default_template"

					// Save default to host
					if err := createDefaultProfilesYaml(profilesPath); err != nil {
						logger.Warn("Failed to save default profiles.yaml", "error", err)
					}
				}
			} else {
				// Other error reading file
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
			Message: fmt.Sprintf("Loaded from: %s", source),
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
