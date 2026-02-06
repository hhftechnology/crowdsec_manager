package api

import (
	"crowdsec-manager/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

// registerHealthRoutes configures endpoints for system and CrowdSec health monitoring.
func registerHealthRoutes(router *gin.RouterGroup, deps *Dependencies) {
	health := router.Group("/health")
	{
		health.GET("/stack", handlers.CheckStackHealth(deps.Docker, deps.Config))
		health.GET("/crowdsec", handlers.CheckCrowdSecHealth(deps.Docker, deps.Config))
		health.GET("/complete", handlers.RunCompleteDiagnostics(deps.Docker, deps.DB, deps.Config, deps.ProxyAdapter))
		health.GET("/proxy", handlers.CheckProxyHealth(deps.ProxyAdapter))
	}
}
