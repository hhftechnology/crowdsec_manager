package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/go-chi/chi/v5"
)

// RegisterConfigurationRoutes mounts configuration management endpoints.
func RegisterConfigurationRoutes(r chi.Router, deps *api.Dependencies) {
	r.Route("/api/configuration", func(r chi.Router) {
		r.Get("/", handleGetConfiguration(deps))
		r.Put("/", handleUpdateConfiguration(deps))
	})
}

func handleGetConfiguration(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		settings, err := deps.DB.GetAllSettings()
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}
		api.JSON(w, http.StatusOK, api.Success(settings))
	}
}

func handleUpdateConfiguration(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var settings map[string]string
		if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("invalid request body"))
			return
		}

		for key, value := range settings {
			if err := deps.DB.SetSetting(key, value); err != nil {
				api.JSON(w, http.StatusInternalServerError, api.Err(err))
				return
			}
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("configuration updated"))
	}
}
