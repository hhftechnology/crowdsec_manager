package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/go-chi/chi/v5"
)

type cleanupRequest struct {
	Retention int `json:"retention"`
}

// RegisterBackupsRoutes mounts backup management endpoints.
func RegisterBackupsRoutes(r chi.Router, deps *api.Dependencies) {
	r.Route("/api/backups", func(r chi.Router) {
		r.Get("/", handleListBackups(deps))
		r.Post("/", handleCreateBackup(deps))
		r.Post("/{name}/restore", handleRestoreBackup(deps))
		r.Delete("/{name}", handleDeleteBackup(deps))
		r.Post("/cleanup", handleCleanupBackups(deps))
	})
}

func handleListBackups(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		backups, err := deps.BackupManager.List()
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}
		api.JSON(w, http.StatusOK, api.Success(backups))
	}
}

func handleCreateBackup(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info, err := deps.BackupManager.Create(r.Context())
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}
		api.JSON(w, http.StatusCreated, api.SuccessWithMessage(info, "backup created"))
	}
}

func handleRestoreBackup(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if name == "" {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("backup name required"))
			return
		}

		if err := deps.BackupManager.Restore(r.Context(), name); err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("backup restored: "+name))
	}
}

func handleDeleteBackup(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		if name == "" {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("backup name required"))
			return
		}

		if err := deps.BackupManager.Delete(name); err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("backup deleted: "+name))
	}
}

func handleCleanupBackups(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req cleanupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("invalid request body"))
			return
		}

		if req.Retention <= 0 {
			req.Retention = 5
		}

		if err := deps.BackupManager.Cleanup(req.Retention); err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("backup cleanup complete"))
	}
}
