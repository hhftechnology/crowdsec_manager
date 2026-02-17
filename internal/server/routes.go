package server

import (
	"github.com/crowdsecurity/crowdsec-manager/internal/api"
	"github.com/crowdsecurity/crowdsec-manager/internal/handlers"
	"github.com/go-chi/chi/v5"
)

// RegisterAll registers every API handler group on the given router.
func RegisterAll(r chi.Router, deps *api.Dependencies) {
	handlers.RegisterDashboardRoutes(r, deps)
	handlers.RegisterHealthRoutes(r, deps)
	handlers.RegisterIPRoutes(r, deps)
	handlers.RegisterWhitelistRoutes(r, deps)
	handlers.RegisterAllowlistRoutes(r, deps)
	handlers.RegisterScenariosRoutes(r, deps)
	handlers.RegisterCaptchaRoutes(r, deps)
	handlers.RegisterDecisionsRoutes(r, deps)
	handlers.RegisterAlertsRoutes(r, deps)
	handlers.RegisterLogsRoutes(r, deps)
	handlers.RegisterBackupsRoutes(r, deps)
	handlers.RegisterServicesRoutes(r, deps)
	handlers.RegisterConfigurationRoutes(r, deps)
	handlers.RegisterNotificationsRoutes(r, deps)
	handlers.RegisterProfilesRoutes(r, deps)
	handlers.RegisterProxyRoutes(r, deps)
}
