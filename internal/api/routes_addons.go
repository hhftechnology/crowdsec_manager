package api

import (
	"crowdsec-manager/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

// registerAddonRoutes configures endpoints for Traefik add-on management (Pangolin/Gerbil).
func registerAddonRoutes(router *gin.RouterGroup, deps *Dependencies) {
	addons := router.Group("/addons")
	{
		addons.GET("", handlers.GetAvailableAddons(deps.ProxyAdapter, deps.Config))
		addons.GET("/:addon/status", handlers.GetAddonStatus(deps.Docker, deps.Config))
		addons.GET("/:addon/config", handlers.GetAddonConfiguration(deps.Config))
		addons.POST("/:addon/enable", handlers.EnableAddon(deps.ComposeManager, deps.Config))
		addons.POST("/:addon/disable", handlers.DisableAddon(deps.ComposeManager, deps.Config))
	}
}
