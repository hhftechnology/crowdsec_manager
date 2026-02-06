package api

import (
	"crowdsec-manager/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

// registerProxyRoutes configures endpoints for proxy management and information.
func registerProxyRoutes(router *gin.RouterGroup, deps *Dependencies) {
	proxyRoutes := router.Group("/proxy")
	{
		proxyRoutes.GET("/types", handlers.GetProxyTypes())
		proxyRoutes.GET("/current", handlers.GetCurrentProxy(deps.ProxyAdapter, deps.Config))
		proxyRoutes.GET("/features", handlers.GetProxyFeatures(deps.ProxyAdapter))
		proxyRoutes.POST("/configure", handlers.ConfigureProxy(deps.ProxyManager))
		proxyRoutes.GET("/health", handlers.CheckProxyHealth(deps.ProxyAdapter))

		// Bouncer integration endpoints
		proxyRoutes.GET("/bouncer/status", handlers.GetBouncerStatus(deps.ProxyAdapter))
		proxyRoutes.POST("/bouncer/validate", handlers.ValidateBouncerConfiguration(deps.ProxyAdapter))
	}
}
