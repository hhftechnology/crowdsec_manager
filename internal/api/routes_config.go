package api

import (
	"crowdsec-manager/internal/api/dto"
	"crowdsec-manager/internal/api/handlers"
	"net/http"

	"github.com/gin-gonic/gin"
)

// registerConfigRoutes configures endpoints for application settings and file content.
func registerConfigRoutes(router *gin.RouterGroup, deps *Dependencies) {
	configGroup := router.Group("/config")
	{
		configGroup.GET("/settings", func(c *gin.Context) {
			settings, err := deps.DB.GetSettings()
			if err != nil {
				c.JSON(http.StatusInternalServerError, dto.Err(err))
				return
			}
			c.JSON(http.StatusOK, dto.Success(settings))
		})
		configGroup.PUT("/settings", handlers.UpdateSettings(deps.DB))
		configGroup.GET("/files/:container/:fileType", handlers.GetFileContent(deps.Docker, deps.DB))
	}
}
