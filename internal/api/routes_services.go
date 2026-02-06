package api

import (
	"crowdsec-manager/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

// registerServicesRoutes configures endpoints for Docker service management.
func registerServicesRoutes(router *gin.RouterGroup, deps *Dependencies) {
	services := router.Group("/services")
	{
		services.GET("/verify", handlers.VerifyServices(deps.Docker, deps.Config))
		services.POST("/shutdown", handlers.GracefulShutdown(deps.Docker, deps.Config))
		services.POST("/action", handlers.ServiceAction(deps.Docker, deps.Config))
	}
}
