package handlers

import (
	"net/http"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/go-chi/chi/v5"
)

// RegisterServicesRoutes mounts container service management endpoints.
func RegisterServicesRoutes(r chi.Router, deps *api.Dependencies) {
	r.Route("/api/services", func(r chi.Router) {
		r.Get("/", handleListServices(deps))
		r.Post("/{name}/start", handleStartService(deps))
		r.Post("/{name}/stop", handleStopService(deps))
		r.Post("/{name}/restart", handleRestartService(deps))
	})
}

func handleListServices(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		containers, err := deps.Docker.ListContainers(r.Context())
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}
		api.JSON(w, http.StatusOK, api.Success(containers))
	}
}

func handleStartService(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if name == "" {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("service name required"))
			return
		}

		if err := deps.Docker.StartContainer(r.Context(), name); err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("service started: "+name))
	}
}

func handleStopService(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if name == "" {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("service name required"))
			return
		}

		if err := deps.Docker.StopContainer(r.Context(), name); err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("service stopped: "+name))
	}
}

func handleRestartService(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if name == "" {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("service name required"))
			return
		}

		if err := deps.Docker.RestartContainer(r.Context(), name); err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("service restarted: "+name))
	}
}
