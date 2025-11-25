package handlers

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

// DiscordTemplate is the template for discord.yaml
const DiscordTemplate = `
type: http
name: discord
log_level: info
format: |
  {
    "embeds": [
      {
        {{range . -}}
        {{$alert := . -}}
        {{range .Decisions -}}
        {{- $cti := .Value | CrowdsecCTI  -}}
        "timestamp": "{{$alert.StartAt}}",
        "title": "Crowdsec Alert",
        "color": 16711680,
        "description": "Potential threat detected. View details in [Crowdsec Console](<https://app.crowdsec.net/cti/{{.Value}}>)",
        "url": "https://app.crowdsec.net/cti/{{.Value}}",
        {{if $alert.Source.Cn -}}
        "image": {
          "url": "https://maps.geoapify.com/v1/staticmap?style=osm-bright-grey&width=600&height=400&center=lonlat:{{$alert.Source.Longitude}},{{$alert.Source.Latitude}}&zoom=8.1848&marker=lonlat:{{$alert.Source.Longitude}},{{$alert.Source.Latitude}};type:awesome;color:%23655e90;size:large;icon:industry|lonlat:{{$alert.Source.Longitude}},{{$alert.Source.Latitude}};type:material;color:%23ff3421;icontype:awesome&scaleFactor=2&apiKey={{env "GEOAPIFY_API_KEY"}}"
        },
        {{end}}
        "fields": [
              {
                "name": "Scenario",
                "value": "` + "`{{ .Scenario }}`" + `",
                "inline": "true"
              },
              {
                "name": "IP",
                "value": "[{{.Value}}](<https://www.whois.com/whois/{{.Value}}>)",
                "inline": "true"
              },
              {
                "name": "Ban Duration",
                "value": "{{.Duration}}",
                "inline": "true"
              },
              {{if $alert.Source.Cn -}}
              { 
                "name": "Country",
                "value": "{{$alert.Source.Cn}} :flag_{{ $alert.Source.Cn | lower }}:",
                "inline": "true"
              }
              {{if $cti.Location.City -}}
              ,
              { 
                "name": "City",
                "value": "{{$cti.Location.City}}",
                "inline": "true"
              },
              { 
                "name": "Maliciousness",
                "value": "{{mulf $cti.GetMaliciousnessScore 100 | floor}} %",
                "inline": "true"
              }
              {{end}}
              {{end}}
              {{if not $alert.Source.Cn -}}
              { 
                "name": "Location",
                "value": "Unknown :pirate_flag:"
              }
              {{end}}
              {{end -}}
              {{end -}}
              {{range . -}}
              {{$alert := . -}}
              {{range .Meta -}}
                ,{
                "name": "{{.Key}}",
                "value": "{{ (splitList "," (.Value | replace "\"" "` + "`" + `" | replace "[" "" |replace "]" "")) | join "\\n"}}"
              } 
              {{end -}}
              {{end -}}
        ]
      }
    ]
  }
url: https://discord.com/api/webhooks/{{.WebhookID}}/{{.WebhookToken}}
method: POST
headers:
  Content-Type: application/json
`

// GetDiscordConfig retrieves the current Discord configuration
func GetDiscordConfig(db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		settings, err := db.GetSettings()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get settings: %v", err),
			})
			return
		}

		// Check if enabled in profiles.yaml
		enabled := false
		profilesPath := filepath.Join(cfg.ConfigDir, "crowdsec", "profiles.yaml")
		if _, err := os.Stat(profilesPath); err == nil {
			enabled, _ = isDiscordEnabled(profilesPath)
		}

		config := models.DiscordConfig{
			Enabled:      enabled,
			WebhookID:    settings.DiscordWebhookID,
			WebhookToken: settings.DiscordWebhookToken,
			GeoapifyKey:  settings.GeoapifyKey,
			CTIKey:       settings.CTIKey,
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    config,
		})
	}
}

// UpdateDiscordConfig updates the Discord configuration
func UpdateDiscordConfig(db *database.Database, cfg *config.Config, dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.DiscordConfig
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		// Update database
		settings, err := db.GetSettings()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get settings: %v", err),
			})
			return
		}

		settings.DiscordWebhookID = req.WebhookID
		settings.DiscordWebhookToken = req.WebhookToken
		settings.GeoapifyKey = req.GeoapifyKey
		settings.CTIKey = req.CTIKey

		if err := db.UpdateSettings(settings); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update settings: %v", err),
			})
			return
		}

		// Generate discord.yaml
		discordPath := filepath.Join(cfg.ConfigDir, "crowdsec", "notifications", "discord.yaml")
		if err := generateDiscordYaml(discordPath, req); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to generate discord.yaml: %v", err),
			})
			return
		}

		// Update profiles.yaml
		profilesPath := filepath.Join(cfg.ConfigDir, "crowdsec", "profiles.yaml")
		if err := updateProfilesYaml(profilesPath, req.Enabled); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update profiles.yaml: %v", err),
			})
			return
		}

		// Restart CrowdSec if requested
		restarted := false
		if req.CrowdSecRestarted {
			if err := dockerClient.RestartContainerWithTimeout(cfg.CrowdsecContainerName, 30); err != nil {
				logger.Error("Failed to restart CrowdSec", "error", err)
				// Don't fail the request, just note it
			} else {
				restarted = true
			}
		}

		req.CrowdSecRestarted = restarted
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Discord configuration updated successfully",
			Data:    req,
		})
	}
}

// Helper functions

func generateDiscordYaml(path string, config models.DiscordConfig) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Parse template
	tmpl, err := template.New("discord").Parse(DiscordTemplate)
	if err != nil {
		return err
	}

	// Create file
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Execute template
	return tmpl.Execute(f, config)
}

func isDiscordEnabled(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	var profiles map[string]interface{}
	if err := yaml.Unmarshal(data, &profiles); err != nil {
		return false, err
	}

	// This is a simplified check. Real profiles.yaml structure is complex.
	// We assume a standard structure where we look for 'notifications' list in the first profile or all profiles.
	// But yaml.Unmarshal into map[string]interface{} might be too generic.
	// Let's try to find "discord" in the file content as a simple heuristic first, 
	// or better, parse it properly.
	
	// Since we are modifying it, we should parse it properly.
	// However, the structure of profiles.yaml can vary.
	// Let's define a minimal struct for what we need.
	
	// Re-reading file for proper parsing
	return strings.Contains(string(data), "- discord"), nil
}

func updateProfilesYaml(path string, enable bool) error {
	// Reading the file
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	content := string(data)
	hasDiscord := strings.Contains(content, "- discord")

	if enable && !hasDiscord {
		// Add discord to notifications
		// We look for "notifications:" and add "- discord" under it.
		// This is a bit brittle with string replacement but safer than re-marshalling which might lose comments/formatting.
		if strings.Contains(content, "notifications:") {
			lines := strings.Split(content, "\n")
			var newLines []string
			for _, line := range lines {
				newLines = append(newLines, line)
				if strings.TrimSpace(line) == "notifications:" {
					// Check indentation
					indent := ""
					for _, char := range line {
						if char == ' ' || char == '\t' {
							indent += string(char)
						} else {
							break
						}
					}
					newLines = append(newLines, indent+"  - discord")
				}
			}
			return os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0644)
		} else {
			// If no notifications section, we might need to add it to the default profile.
			// This is getting complicated. Let's append to the end if we can't find it?
			// No, that's risky.
			// Let's assume standard profiles.yaml has "notifications:"
			return fmt.Errorf("could not find 'notifications:' section in profiles.yaml")
		}
	} else if !enable && hasDiscord {
		// Remove discord
		lines := strings.Split(content, "\n")
		var newLines []string
		for _, line := range lines {
			if strings.Contains(line, "- discord") {
				continue
			}
			newLines = append(newLines, line)
		}
		return os.WriteFile(path, []byte(strings.Join(newLines, "\n")), 0644)
	}

	return nil
}
