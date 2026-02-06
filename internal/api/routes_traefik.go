package api

import (
	"crowdsec-manager/internal/api/handlers"
	"crowdsec-manager/internal/api/middleware"

	"github.com/gin-gonic/gin"
)

// registerTraefikRoutes configures legacy Traefik-specific endpoints.
// All routes in this group are deprecated in favor of proxy-generic equivalents.
func registerTraefikRoutes(router *gin.RouterGroup, deps *Dependencies) {
	traefik := router.Group("/traefik")
	{
		traefik.GET("/config",
			middleware.Deprecated("/api/proxy/current"),
			handlers.GetTraefikConfig(),
		)
		traefik.GET("/config-path",
			middleware.Deprecated("/api/proxy/current"),
			handlers.GetTraefikConfigPath(deps.DB),
		)
		traefik.POST("/config-path",
			middleware.Deprecated("/api/proxy/configure"),
			handlers.SetTraefikConfigPath(deps.DB),
		)
	}
}
