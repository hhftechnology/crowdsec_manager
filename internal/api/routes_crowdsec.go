package api

import (
	"crowdsec-manager/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

// registerCrowdSecRoutes configures endpoints for CrowdSec-specific operations
// including bouncers, decisions, metrics, alerts, and console enrollment.
func registerCrowdSecRoutes(router *gin.RouterGroup, deps *Dependencies) {
	crowdsec := router.Group("/crowdsec")
	{
		// Bouncer management
		crowdsec.GET("/bouncers", handlers.GetBouncers(deps.Docker, deps.Config))
		crowdsec.POST("/bouncers", handlers.AddBouncer(deps.Docker, deps.Config))
		crowdsec.DELETE("/bouncers/:name", handlers.DeleteBouncer(deps.Docker, deps.Config))

		// Decision management
		crowdsec.GET("/decisions", handlers.GetDecisions(deps.Docker, deps.Config))
		crowdsec.POST("/decisions", handlers.AddDecision(deps.Docker, deps.Config))
		crowdsec.DELETE("/decisions", handlers.DeleteDecision(deps.Docker, deps.Config))
		crowdsec.POST("/decisions/import", handlers.ImportDecisions(deps.Docker, deps.Config))

		// Analysis
		crowdsec.GET("/decisions/analysis", handlers.GetDecisionsAnalysis(deps.Docker, deps.Config))
		crowdsec.GET("/alerts/analysis", handlers.GetAlertsAnalysis(deps.Docker, deps.Config))

		// Metrics
		crowdsec.GET("/metrics", handlers.GetMetrics(deps.Docker, deps.Config))

		// Console enrollment
		crowdsec.POST("/enroll", handlers.EnrollCrowdSec(deps.Docker, deps.Config))
		crowdsec.GET("/status", handlers.GetCrowdSecEnrollmentStatus(deps.Docker, deps.Config))
		crowdsec.POST("/console/enable", handlers.EnableConsoleManagement(deps.Docker, deps.Config))
	}
}
