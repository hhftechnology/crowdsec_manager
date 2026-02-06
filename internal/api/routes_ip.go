package api

import (
	"crowdsec-manager/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

// registerIPRoutes configures endpoints for IP banning, unbanning, and public IP retrieval.
func registerIPRoutes(router *gin.RouterGroup, deps *Dependencies) {
	ip := router.Group("/ip")
	{
		ip.GET("/public", handlers.GetPublicIP())
		ip.GET("/blocked/:ip", handlers.IsIPBlocked(deps.Docker, deps.Config))
		ip.GET("/security/:ip", handlers.CheckIPSecurity(deps.Docker, deps.Config))
		ip.POST("/unban", handlers.UnbanIP(deps.Docker, deps.Config))
	}
}
