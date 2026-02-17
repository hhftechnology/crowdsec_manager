package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/go-chi/chi/v5"
)

// RegisterAlertsRoutes mounts alert listing endpoints.
func RegisterAlertsRoutes(r chi.Router, deps *api.Dependencies) {
	r.Get("/api/alerts", handleListAlerts(deps))
}

func handleListAlerts(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cmd := []string{"cscli", "alerts", "list", "-o", "json"}

		if ip := r.URL.Query().Get("ip"); ip != "" {
			cmd = append(cmd, "--ip", ip)
		}
		if scope := r.URL.Query().Get("scope"); scope != "" {
			cmd = append(cmd, "--scope", scope)
		}

		output, err := deps.Docker.ExecInContainer(r.Context(), deps.Config.CrowdSecContainer, cmd)
		if err != nil {
			api.JSON(w, http.StatusOK, api.Success([]interface{}{}))
			return
		}

		var data interface{}
		if json.Unmarshal([]byte(output), &data) != nil {
			data = []interface{}{}
		}
		api.JSON(w, http.StatusOK, api.Success(data))
	}
}
