package handlers

import (
	"io"
	"net/http"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/go-chi/chi/v5"
)

const profilesPath = "/etc/crowdsec/profiles.yaml"

// RegisterProfilesRoutes mounts CrowdSec profile management endpoints.
func RegisterProfilesRoutes(r chi.Router, deps *api.Dependencies) {
	r.Route("/api/profiles", func(r chi.Router) {
		r.Get("/", handleGetProfiles(deps))
		r.Put("/", handleUpdateProfiles(deps))
	})
}

func handleGetProfiles(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := deps.Docker.ReadFileFromContainer(
			r.Context(),
			deps.Config.CrowdSecContainer,
			profilesPath,
		)
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.Success(map[string]string{
			"content": string(data),
		}))
	}
}

func handleUpdateProfiles(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("failed to read request body"))
			return
		}

		if len(body) == 0 {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("profiles content cannot be empty"))
			return
		}

		err = deps.Docker.WriteFileToContainer(
			r.Context(),
			deps.Config.CrowdSecContainer,
			profilesPath,
			body,
		)
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("profiles updated"))
	}
}
