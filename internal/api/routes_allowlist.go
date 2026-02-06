package api

import (
	"crowdsec-manager/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

// registerAllowlistRoutes configures endpoints for managing CrowdSec allowlists (CRUD operations).
func registerAllowlistRoutes(router *gin.RouterGroup, deps *Dependencies) {
	allowlist := router.Group("/allowlist")
	{
		allowlist.GET("/list", handlers.ListAllowlists(deps.Docker, deps.Config))
		allowlist.POST("/create", handlers.CreateAllowlist(deps.Docker, deps.Config))
		allowlist.GET("/inspect/:name", handlers.InspectAllowlist(deps.Docker, deps.Config))
		allowlist.POST("/add", handlers.AddAllowlistEntries(deps.Docker, deps.Config))
		allowlist.POST("/remove", handlers.RemoveAllowlistEntries(deps.Docker, deps.Config))
		allowlist.DELETE("/:name", handlers.DeleteAllowlist(deps.Docker, deps.Config))
	}
}
