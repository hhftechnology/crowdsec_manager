package api

import (
	"crowdsec-manager/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

// registerCaptchaRoutes configures endpoints for proxy captcha setup and status.
func registerCaptchaRoutes(router *gin.RouterGroup, deps *Dependencies) {
	captcha := router.Group("/captcha")
	{
		captcha.POST("/setup", handlers.SetupCaptcha(deps.Docker, deps.Config, deps.ProxyAdapter))
		captcha.GET("/status", handlers.GetCaptchaStatus(deps.Docker, deps.DB, deps.Config, deps.ProxyAdapter))
	}
}
