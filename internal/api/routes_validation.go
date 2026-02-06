package api

import (
	"crowdsec-manager/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

// registerValidationRoutes configures endpoints for environment variable and path validation.
func registerValidationRoutes(router *gin.RouterGroup, deps *Dependencies) {
	// Complete validation
	router.GET("/config/validate/complete", handlers.ValidateComplete(deps.Config, deps.Docker))
	router.GET("/config/summary", handlers.GetValidationSummary(deps.Config, deps.Docker))
	router.GET("/config/suggestions", handlers.GetSuggestions(deps.Config, deps.Docker))

	// Environment variables
	router.GET("/config/env", handlers.GetEnvVars(deps.Config))
	router.POST("/config/env/validate", handlers.ValidateEnv(deps.Config, deps.Docker))
	router.GET("/config/env/required", handlers.GetRequiredEnvVars(deps.Config))
	router.GET("/config/env/required/:proxyType", handlers.GetRequiredEnvVars(deps.Config))

	// Path validation
	router.GET("/config/paths/validate/host", handlers.ValidateHostPaths(deps.Config, deps.Docker))
	router.GET("/config/paths/validate/container", handlers.ValidateContainerPaths(deps.Config, deps.Docker))
	router.POST("/config/paths/test", handlers.TestPath())

	// Volume validation
	router.GET("/config/volumes/validate", handlers.ValidateVolumeMappings(deps.Config, deps.Docker))

	// Requirements and export
	router.GET("/config/requirements", handlers.GetProxyRequirements(deps.Config))
	router.GET("/config/requirements/:proxyType", handlers.GetProxyRequirements(deps.Config))
	router.GET("/config/export/env", handlers.ExportEnvFile(deps.Config, deps.Docker))
}
