package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"text/template"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/go-chi/chi/v5"
)

type discordConfig struct {
	WebhookURL string `json:"webhook_url"`
	Username   string `json:"username"`
}

const discordYAMLTemplate = `type: http
name: discord_notification
log_level: info
format: |
  {{` + "`" + `{{ range . -}}` + "`" + `}}
  {{` + "`" + `{{ .Source.Scope }}` + "`" + `}}: {{` + "`" + `{{ .Source.Value }}` + "`" + `}} triggered {{` + "`" + `{{ .Scenario }}` + "`" + `}}
  {{` + "`" + `{{ end -}}` + "`" + `}}
url: "{{ .WebhookURL }}"
method: POST
headers:
  Content-Type: application/json
`

// RegisterNotificationsRoutes mounts notification configuration endpoints.
func RegisterNotificationsRoutes(r chi.Router, deps *api.Dependencies) {
	r.Route("/api/notifications", func(r chi.Router) {
		r.Get("/status", handleNotificationStatus(deps))
		r.Post("/discord", handleDiscordSetup(deps))
		r.Post("/discord/test", handleDiscordTest(deps))
	})
}

func handleNotificationStatus(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if discord notification config exists in CrowdSec container.
		_, err := deps.Docker.ReadFileFromContainer(
			r.Context(),
			deps.Config.CrowdSecContainer,
			"/etc/crowdsec/notifications/discord.yaml",
		)

		configured := err == nil
		webhookURL, _ := deps.DB.GetSetting("discord_webhook_url")

		api.JSON(w, http.StatusOK, api.Success(map[string]interface{}{
			"discord_configured": configured,
			"webhook_url_set":    webhookURL != "",
		}))
	}
}

func handleDiscordSetup(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg discordConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("invalid request body"))
			return
		}

		if cfg.WebhookURL == "" {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("webhook_url is required"))
			return
		}

		// Store the webhook URL.
		if err := deps.DB.SetSetting("discord_webhook_url", cfg.WebhookURL); err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		// Generate discord.yaml.
		tmpl, err := template.New("discord").Parse(discordYAMLTemplate)
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, cfg); err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		// Write to CrowdSec container.
		err = deps.Docker.WriteFileToContainer(
			r.Context(),
			deps.Config.CrowdSecContainer,
			"/etc/crowdsec/notifications/discord.yaml",
			buf.Bytes(),
		)
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("discord notification configured"))
	}
}

func handleDiscordTest(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		webhookURL, err := deps.DB.GetSetting("discord_webhook_url")
		if err != nil || webhookURL == "" {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("discord webhook not configured"))
			return
		}

		// Send a test message via HTTP POST.
		payload := map[string]string{
			"content": "CrowdSec Manager test notification - connection successful!",
		}
		body, _ := json.Marshal(payload)

		resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(fmt.Errorf("send test: %w", err)))
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			api.JSON(w, http.StatusBadGateway, api.ErrMsg(fmt.Sprintf("discord returned status %d", resp.StatusCode)))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("test notification sent"))
	}
}
