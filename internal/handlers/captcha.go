package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/crowdsecurity/crowdsec-manager/internal/proxy"
	"github.com/go-chi/chi/v5"
)

// RegisterCaptchaRoutes mounts captcha configuration endpoints.
func RegisterCaptchaRoutes(r chi.Router, deps *api.Dependencies) {
	r.Route("/api/captcha", func(r chi.Router) {
		r.Get("/status", handleCaptchaStatus(deps))
		r.Post("/", handleCaptchaSetup(deps))
		r.Delete("/", handleCaptchaDisable(deps))
	})
}

func handleCaptchaStatus(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adapter := deps.ProxyManager.Adapter()
		if adapter == nil {
			api.JSON(w, http.StatusOK, api.Success(proxy.CaptchaStatus{}))
			return
		}

		status, err := adapter.CaptchaManager().Status(r.Context())
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}
		api.JSON(w, http.StatusOK, api.Success(status))
	}
}

func handleCaptchaSetup(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var cfg proxy.CaptchaConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("invalid request body"))
			return
		}

		if cfg.Provider == "" || cfg.SiteKey == "" {
			api.JSON(w, http.StatusBadRequest, api.ErrMsg("provider and site_key are required"))
			return
		}

		adapter := deps.ProxyManager.Adapter()
		if adapter == nil {
			api.JSON(w, http.StatusServiceUnavailable, api.ErrMsg("no proxy adapter available"))
			return
		}

		if err := adapter.CaptchaManager().Setup(r.Context(), cfg); err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("captcha configured"))
	}
}

func handleCaptchaDisable(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adapter := deps.ProxyManager.Adapter()
		if adapter == nil {
			api.JSON(w, http.StatusServiceUnavailable, api.ErrMsg("no proxy adapter available"))
			return
		}

		if err := adapter.CaptchaManager().Disable(r.Context()); err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}

		api.JSON(w, http.StatusOK, api.SuccessMessage("captcha disabled"))
	}
}
