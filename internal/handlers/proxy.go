package handlers

import (
	"net/http"

	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/crowdsecurity/crowdsec-manager/internal/config"
	"github.com/go-chi/chi/v5"
)

// RegisterProxyRoutes mounts proxy information endpoints.
func RegisterProxyRoutes(r chi.Router, deps *api.Dependencies) {
	r.Get("/api/proxy/info", handleProxyInfo(deps))
}

func handleProxyInfo(deps *api.Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		adapter := deps.ProxyManager.Adapter()
		if adapter == nil {
			api.JSON(w, http.StatusOK, api.Success(map[string]interface{}{
				"type":     "standalone",
				"name":     "Standalone",
				"features": []string{},
			}))
			return
		}

		api.JSON(w, http.StatusOK, api.Success(map[string]interface{}{
			"type":     string(adapter.Type()),
			"name":     adapter.Name(),
			"features": adapter.SupportedFeatures(),
			"paths":    config.GetPaths(string(adapter.Type())),
		}))
	}
}
