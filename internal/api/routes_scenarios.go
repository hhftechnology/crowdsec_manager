package api

import (
	"crowdsec-manager/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

// registerScenarioRoutes configures endpoints for managing custom CrowdSec scenarios.
func registerScenarioRoutes(router *gin.RouterGroup, deps *Dependencies) {
	scenarios := router.Group("/scenarios")
	{
		scenarios.POST("/setup", handlers.SetupCustomScenarios(deps.Docker, deps.Config.ConfigDir, deps.Config))
		scenarios.GET("/list", handlers.ListScenarios(deps.Docker, deps.Config))
		scenarios.GET("/files", handlers.GetScenarioFiles(deps.Config.ConfigDir))
		scenarios.DELETE("/file", handlers.DeleteScenarioFile(deps.Docker, deps.Config.ConfigDir, deps.Config))
	}
}
