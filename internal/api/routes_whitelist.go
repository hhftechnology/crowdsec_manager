package api

import (
	"crowdsec-manager/internal/api/handlers"
	"crowdsec-manager/internal/api/middleware"

	"github.com/gin-gonic/gin"
)

// registerWhitelistRoutes configures endpoints for adding IPs to CrowdSec and proxy whitelists.
func registerWhitelistRoutes(router *gin.RouterGroup, deps *Dependencies) {
	whitelist := router.Group("/whitelist")
	{
		whitelist.GET("/view", handlers.ViewWhitelist(deps.Docker, deps.Config, deps.ProxyAdapter))
		whitelist.POST("/current", handlers.WhitelistCurrentIP(deps.Docker, deps.Config, deps.ProxyAdapter))
		whitelist.POST("/manual", handlers.WhitelistManualIP(deps.Docker, deps.Config, deps.ProxyAdapter))
		whitelist.POST("/cidr", handlers.WhitelistCIDR(deps.Docker, deps.Config, deps.ProxyAdapter))
		whitelist.POST("/crowdsec", handlers.AddToCrowdSecWhitelist(deps.Docker, deps.Config))

		// Legacy Traefik-specific endpoint (deprecated)
		whitelist.POST("/traefik",
			middleware.Deprecated("/api/whitelist/proxy"),
			handlers.AddToTraefikWhitelist(deps.Docker, deps.Config),
		)

		// Generic proxy whitelist endpoint (preferred)
		whitelist.POST("/proxy", handlers.AddToProxyWhitelist(deps.ProxyAdapter))
		whitelist.POST("/comprehensive", handlers.SetupComprehensiveWhitelist(deps.Docker, deps.Config, deps.ProxyAdapter))
	}
}
