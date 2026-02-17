package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/go-chi/chi/v5"
)

// RegisterDecisionsRoutes mounts decision listing endpoints.
func RegisterDecisionsRoutes(r chi.Router, deps *api.Dependencies) {
	r.Get("/api/decisions", handleListDecisions(deps))
}

func handleListDecisions(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cmd := []string{"cscli", "decisions", "list", "-o", "json"}

		// Apply optional query filters.
		if ip := r.URL.Query().Get("ip"); ip != "" {
			cmd = append(cmd, "--ip", ip)
		}
		if scope := r.URL.Query().Get("scope"); scope != "" {
			cmd = append(cmd, "--scope", scope)
		}
		if dtype := r.URL.Query().Get("type"); dtype != "" {
			cmd = append(cmd, "--type", dtype)
		}

		output, err := deps.Docker.ExecInContainer(r.Context(), deps.Config.CrowdSecContainer, cmd)
		if err != nil {
			// No decisions found returns exit code 1.
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
