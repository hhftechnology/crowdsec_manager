package api

import (
	"crowdsec-manager/internal/api/handlers"
	"crowdsec-manager/internal/cache"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/messaging"

	"github.com/gin-gonic/gin"
)

// RegisterHealthRoutes configures endpoints for system and CrowdSec health monitoring
func RegisterHealthRoutes(router *gin.RouterGroup, dockerClient *docker.Client, cfg *config.Config) {
	health := router.Group("/health")
	{
		health.GET("/stack", handlers.CheckStackHealth(dockerClient, cfg))
		health.GET("/crowdsec", handlers.CheckCrowdSecHealth(dockerClient, cfg))
		health.GET("/complete", handlers.RunCompleteDiagnostics(dockerClient, cfg))
	}
}

// RegisterAllowlistRoutes configures endpoints for managing CrowdSec allowlists (CRUD operations)
func RegisterAllowlistRoutes(router *gin.RouterGroup, dockerClient *docker.Client, cfg *config.Config) {
	allowlist := router.Group("/allowlist")
	{
		allowlist.GET("/list", handlers.ListAllowlists(dockerClient, cfg))
		allowlist.POST("/create", handlers.CreateAllowlist(dockerClient, cfg))
		allowlist.GET("/inspect/:name", handlers.InspectAllowlist(dockerClient, cfg))
		allowlist.POST("/add", handlers.AddAllowlistEntries(dockerClient, cfg))
		allowlist.POST("/remove", handlers.RemoveAllowlistEntries(dockerClient, cfg))
		allowlist.POST("/import", handlers.ImportAllowlistEntries(dockerClient, cfg))
		allowlist.DELETE("/:name", handlers.DeleteAllowlist(dockerClient, cfg))
	}
}

// RegisterScenarioRoutes configures endpoints for managing custom CrowdSec scenarios
func RegisterScenarioRoutes(router *gin.RouterGroup, dockerClient *docker.Client, configDir string, cfg *config.Config) {
	scenarios := router.Group("/scenarios")
	{
		scenarios.POST("/setup", handlers.SetupCustomScenarios(dockerClient, configDir, cfg))
		scenarios.GET("/list", handlers.ListScenarios(dockerClient, cfg))
		scenarios.GET("/files", handlers.GetScenarioFiles(configDir))
		scenarios.DELETE("/file", handlers.DeleteScenarioFile(dockerClient, configDir, cfg))
	}
}

// RegisterLogRoutes configures endpoints for viewing container logs
func RegisterLogRoutes(router *gin.RouterGroup, dockerClient *docker.Client, cfg *config.Config) {
	logs := router.Group("/logs")
	{
		logs.GET("/crowdsec", handlers.GetCrowdSecLogs(dockerClient, cfg))
		logs.GET("/:service", handlers.GetServiceLogs(dockerClient, cfg))
		logs.GET("/stream/:service", handlers.StreamLogs(dockerClient, cfg))
		logs.GET("/structured/:service", handlers.GetStructuredLogs(dockerClient, cfg))
	}
}

// RegisterServicesRoutes configures endpoints for Docker service management and CrowdSec operations
func RegisterServicesRoutes(router *gin.RouterGroup, dockerClient *docker.Client, db *database.Database, cfg *config.Config, ttlCache ...*cache.TTLCache) {
	var c *cache.TTLCache
	if len(ttlCache) > 0 {
		c = ttlCache[0]
	}

	services := router.Group("/services")
	{
		services.GET("/verify", handlers.VerifyServices(dockerClient, cfg))
		services.POST("/shutdown", handlers.GracefulShutdown(dockerClient, cfg))
		services.POST("/action", handlers.ServiceAction(dockerClient, cfg))
	}

	crowdsec := router.Group("/crowdsec")
	{
		crowdsec.GET("/bouncers", handlers.GetBouncers(dockerClient, cfg))
		crowdsec.POST("/bouncers", handlers.AddBouncer(dockerClient, cfg))
		crowdsec.DELETE("/bouncers/:name", handlers.DeleteBouncer(dockerClient, cfg))
		crowdsec.GET("/decisions", handlers.GetDecisions(dockerClient, cfg, c))
		crowdsec.POST("/decisions", handlers.AddDecision(dockerClient, cfg))
		crowdsec.DELETE("/decisions", handlers.DeleteDecision(dockerClient, cfg))
		crowdsec.POST("/decisions/import", handlers.ImportDecisions(dockerClient, cfg))
		crowdsec.GET("/decisions/analysis", handlers.GetDecisionsAnalysis(dockerClient, cfg))
		crowdsec.GET("/decisions/history", handlers.GetDecisionHistory())
		crowdsec.GET("/decisions/repeated-offenders", handlers.GetRepeatedOffenders())
		crowdsec.POST("/decisions/history/reapply", handlers.ReapplyDecision(dockerClient, cfg))
		crowdsec.POST("/decisions/history/bulk-reapply", handlers.BulkReapplyDecisions(dockerClient, cfg))
		crowdsec.GET("/history/stats", handlers.GetHistoryStats())
		crowdsec.GET("/alerts/analysis", handlers.GetAlertsAnalysis(dockerClient, cfg, c))
		crowdsec.GET("/alerts/history", handlers.GetAlertHistory())
		crowdsec.GET("/alerts/:id", handlers.InspectAlert(dockerClient, cfg))
		crowdsec.DELETE("/alerts/:id", handlers.DeleteAlert(dockerClient, cfg))
		crowdsec.GET("/history/config", handlers.GetHistoryConfig())
		crowdsec.PUT("/history/config", handlers.UpdateHistoryConfig())
		crowdsec.GET("/metrics", handlers.GetMetrics(dockerClient, cfg, c))
		crowdsec.POST("/enroll", handlers.EnrollCrowdSec(dockerClient, db, cfg))
		crowdsec.POST("/enroll/finalize", handlers.FinalizeCrowdSecEnrollment(dockerClient, cfg))
		crowdsec.GET("/enroll/preferences", handlers.GetCrowdSecEnrollmentPreferences(db))
		crowdsec.PUT("/enroll/preferences", handlers.UpdateCrowdSecEnrollmentPreferences(db))
		crowdsec.GET("/status", handlers.GetCrowdSecEnrollmentStatus(dockerClient, cfg))
	}
}

// RegisterHostRoutes configures endpoints for listing and managing Docker hosts
func RegisterHostRoutes(router *gin.RouterGroup, multiHost *docker.MultiHostClient) {
	hosts := router.Group("/hosts")
	{
		hosts.GET("/list", handlers.ListDockerHosts(multiHost))
	}
}

// RegisterTerminalRoutes configures WebSocket endpoint for interactive container terminals
func RegisterTerminalRoutes(router *gin.RouterGroup, dockerClient *docker.Client) {
	router.GET("/terminal/:container", handlers.TerminalSession(dockerClient))
}

// RegisterHubRoutes configures endpoints for browsing, installing, removing, and upgrading CrowdSec hub items
func RegisterHubRoutes(router *gin.RouterGroup, dockerClient *docker.Client, db *database.Database, cfg *config.Config) {
	hub := router.Group("/hub")
	{
		hub.GET("/list", handlers.ListHubItems(dockerClient, cfg))
		hub.POST("/upgrade", handlers.UpgradeAllHub(dockerClient, db, cfg))
		hub.GET("/categories", handlers.ListHubCategories())
		hub.GET("/:category/items", handlers.ListHubItemsByCategory(dockerClient, cfg))
		hub.POST("/:category/install", handlers.InstallHubItemByCategory(dockerClient, db, cfg))
		hub.POST("/:category/remove", handlers.RemoveHubItemByCategory(dockerClient, db, cfg))
		hub.POST("/:category/manual-apply", handlers.ManualApplyHubYAML(dockerClient, db, cfg))
		hub.GET("/preferences", handlers.GetHubPreferences(db))
		hub.GET("/preferences/:category", handlers.GetHubPreferenceByCategory(db))
		hub.PUT("/preferences/:category", handlers.UpdateHubPreference(db))
		hub.GET("/history", handlers.ListHubOperationHistory(db))
		hub.GET("/history/:id", handlers.GetHubOperationByID(db))
	}
}

// RegisterSimulationRoutes configures endpoints for managing CrowdSec simulation mode
func RegisterSimulationRoutes(router *gin.RouterGroup, dockerClient *docker.Client, cfg *config.Config) {
	simulation := router.Group("/simulation")
	{
		simulation.GET("/status", handlers.GetSimulationStatus(dockerClient, cfg))
		simulation.POST("/toggle", handlers.ToggleSimulation(dockerClient, cfg))
	}
}

// RegisterEventRoutes configures WebSocket and SSE endpoints for real-time event streaming
func RegisterEventRoutes(router *gin.RouterGroup, hub *messaging.Hub) {
	router.GET("/events/ws", handlers.EventsWebSocket(hub))
	router.GET("/events/sse", handlers.EventsSSE(hub))
}
