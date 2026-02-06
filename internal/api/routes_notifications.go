package api

import (
	"crowdsec-manager/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

// registerNotificationRoutes configures endpoints for Discord webhook notification management.
func registerNotificationRoutes(router *gin.RouterGroup, deps *Dependencies) {
	notifications := router.Group("/notifications")
	{
		notifications.GET("/discord", handlers.GetDiscordConfig(deps.DB, deps.Config, deps.Docker))
		notifications.GET("/discord/preview", handlers.PreviewDiscordConfig(deps.DB, deps.Config, deps.Docker))
		notifications.POST("/discord", handlers.UpdateDiscordConfig(deps.DB, deps.Config, deps.Docker))
	}
}
