package api

import (
	"crowdsec-manager/internal/api/handlers"
	"crowdsec-manager/internal/api/middleware"

	"github.com/gin-gonic/gin"
)

// registerLogRoutes configures endpoints for viewing container logs and analyzing proxy access logs.
func registerLogRoutes(router *gin.RouterGroup, deps *Dependencies) {
	logs := router.Group("/logs")
	{
		logs.GET("/crowdsec", handlers.GetCrowdSecLogs(deps.Docker, deps.Config))

		// Legacy Traefik-specific endpoints (deprecated)
		logs.GET("/traefik",
			middleware.Deprecated("/api/logs/proxy"),
			handlers.GetTraefikLogs(deps.Docker, deps.DB, deps.Config),
		)
		logs.GET("/traefik/advanced",
			middleware.Deprecated("/api/logs/proxy/analyze"),
			handlers.AnalyzeTraefikLogsAdvanced(deps.Docker, deps.Config),
		)

		// Generic proxy log endpoints (preferred)
		logs.GET("/proxy", handlers.GetProxyLogs(deps.ProxyAdapter))
		logs.GET("/proxy/analyze", handlers.AnalyzeProxyLogs(deps.ProxyAdapter))

		logs.GET("/:service", handlers.GetServiceLogs(deps.Docker))
		logs.GET("/stream/:service", handlers.StreamLogs(deps.Docker))
	}
}
