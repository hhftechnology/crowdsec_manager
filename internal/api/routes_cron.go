package api

import (
	"crowdsec-manager/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

// registerCronRoutes configures endpoints for creating, listing, and deleting scheduled cron jobs.
func registerCronRoutes(router *gin.RouterGroup, deps *Dependencies) {
	cronRoutes := router.Group("/cron")
	{
		cronRoutes.POST("/setup", handlers.SetupCronJob(deps.CronScheduler))
		cronRoutes.GET("/list", handlers.ListCronJobs(deps.CronScheduler))
		cronRoutes.DELETE("/:id", handlers.DeleteCronJob(deps.CronScheduler))
	}
}
