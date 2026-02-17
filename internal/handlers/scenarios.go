package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/go-chi/chi/v5"
)

// RegisterScenariosRoutes mounts scenario listing endpoints.
func RegisterScenariosRoutes(r chi.Router, deps *api.Dependencies) {
	r.Get("/api/scenarios", handleListScenarios(deps))
}

func handleListScenarios(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		output, err := deps.Docker.ExecInContainer(r.Context(), deps.Config.CrowdSecContainer, []string{
			"cscli", "scenarios", "list", "-o", "json",
		})
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		var data interface{}
		if json.Unmarshal([]byte(output), &data) != nil {
			data = output
		}
		api.JSON(w, http.StatusOK, api.Success(data))
	}
}
