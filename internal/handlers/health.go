package handlers

import (
	"net/http"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/crowdsecurity/crowdsec-manager/internal/config"
	"github.com/go-chi/chi/v5"
)

type proxyInfo struct {
	Type     string      `json:"type"`
	Name     string      `json:"name"`
	Features interface{} `json:"features"`
	Paths    interface{} `json:"paths"`
	Health   interface{} `json:"health"`
}

// RegisterHealthRoutes mounts health check endpoints.
func RegisterHealthRoutes(r chi.Router, deps *api.Dependencies) {
	r.Route("/api/health", func(r chi.Router) {
		r.Get("/containers", handleHealthContainers(deps))
		r.Get("/bouncers", handleHealthBouncers(deps))
		r.Get("/proxy", handleHealthProxy(deps))
	})
}

func handleHealthContainers(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		containers, err := deps.Docker.ListContainers(r.Context())
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}
		api.JSON(w, http.StatusOK, api.Success(containers))
	}
}

func handleHealthBouncers(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adapter := deps.ProxyManager.Adapter()
		if adapter == nil {
			api.JSON(w, http.StatusOK, api.Success([]interface{}{}))
			return
		}
		bouncers, err := adapter.BouncerManager().List(r.Context())
		if err != nil {
			api.JSON(w, http.StatusInternalServerError, api.Err(err))
			return
		}
		api.JSON(w, http.StatusOK, api.Success(bouncers))
	}
}

func handleHealthProxy(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adapter := deps.ProxyManager.Adapter()
		if adapter == nil {
			api.JSON(w, http.StatusOK, api.Success(proxyInfo{Type: "standalone"}))
			return
		}

		var healthResult interface{}
		if h, err := adapter.HealthCheck(r.Context()); err == nil {
			healthResult = h
		}

		info := proxyInfo{
			Type:     string(adapter.Type()),
			Name:     adapter.Name(),
			Features: adapter.SupportedFeatures(),
			Paths:    config.GetPaths(string(adapter.Type())),
			Health:   healthResult,
		}

		api.JSON(w, http.StatusOK, api.Success(info))
	}
}
