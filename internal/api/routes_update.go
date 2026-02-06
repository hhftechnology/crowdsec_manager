package api

import (
	"crowdsec-manager/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

// registerUpdateRoutes configures endpoints for checking and applying Docker image updates.
func registerUpdateRoutes(router *gin.RouterGroup, deps *Dependencies) {
	update := router.Group("/update")
	{
		update.GET("/check", handlers.CheckForUpdates(deps.Docker, deps.Config))
		update.POST("/with-crowdsec", handlers.UpdateWithCrowdSec(deps.Docker, deps.Config))
		update.POST("/without-crowdsec", handlers.UpdateWithoutCrowdSec(deps.Docker, deps.Config))
	}
}
