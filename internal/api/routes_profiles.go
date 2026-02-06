package api

import (
	"crowdsec-manager/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

// registerProfileRoutes configures endpoints for managing profiles.yaml.
func registerProfileRoutes(router *gin.RouterGroup, deps *Dependencies) {
	profiles := router.Group("/profiles")
	{
		profiles.GET("", handlers.GetProfiles(deps.Config, deps.Docker))
		profiles.POST("", handlers.UpdateProfiles(deps.DB, deps.Config, deps.Docker))
	}
}
