package api

import (
	"crowdsec-manager/internal/api/handlers"
	"crowdsec-manager/internal/backup"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"

	"github.com/gin-gonic/gin"
)

// RegisterHealthRoutes registers health check routes
func RegisterHealthRoutes(router *gin.RouterGroup, dockerClient *docker.Client, db *database.Database) {
	health := router.Group("/health")
	{
		health.GET("/stack", handlers.CheckStackHealth(dockerClient))
		health.GET("/complete", handlers.RunCompleteDiagnostics(dockerClient, db))
	}
}

// RegisterIPRoutes registers IP management routes
func RegisterIPRoutes(router *gin.RouterGroup, dockerClient *docker.Client) {
	ip := router.Group("/ip")
	{
		ip.GET("/public", handlers.GetPublicIP())
		ip.GET("/blocked/:ip", handlers.IsIPBlocked(dockerClient))
		ip.GET("/security/:ip", handlers.CheckIPSecurity(dockerClient))
		ip.POST("/unban", handlers.UnbanIP(dockerClient))
	}
}

// RegisterWhitelistRoutes registers whitelist management routes
func RegisterWhitelistRoutes(router *gin.RouterGroup, dockerClient *docker.Client) {
	whitelist := router.Group("/whitelist")
	{
		whitelist.GET("/view", handlers.ViewWhitelist(dockerClient))
		whitelist.POST("/current", handlers.WhitelistCurrentIP(dockerClient))
		whitelist.POST("/manual", handlers.WhitelistManualIP(dockerClient))
		whitelist.POST("/cidr", handlers.WhitelistCIDR(dockerClient))
		whitelist.POST("/crowdsec", handlers.AddToCrowdSecWhitelist(dockerClient))
		whitelist.POST("/traefik", handlers.AddToTraefikWhitelist(dockerClient))
		whitelist.POST("/comprehensive", handlers.SetupComprehensiveWhitelist(dockerClient))
	}
}

// RegisterScenarioRoutes registers scenario management routes
func RegisterScenarioRoutes(router *gin.RouterGroup, dockerClient *docker.Client, configDir string) {
	scenarios := router.Group("/scenarios")
	{
		scenarios.POST("/setup", handlers.SetupCustomScenarios(dockerClient, configDir))
		scenarios.GET("/list", handlers.ListScenarios(dockerClient))
		scenarios.GET("/files", handlers.GetScenarioFiles(configDir))
		scenarios.DELETE("/file", handlers.DeleteScenarioFile(dockerClient, configDir))
	}
}

// RegisterCaptchaRoutes registers captcha setup routes
func RegisterCaptchaRoutes(router *gin.RouterGroup, dockerClient *docker.Client, db *database.Database) {
	captcha := router.Group("/captcha")
	{
		captcha.POST("/setup", handlers.SetupCaptcha(dockerClient))
		captcha.GET("/status", handlers.GetCaptchaStatus(dockerClient, db))
	}
}

// RegisterLogRoutes registers log viewing routes
func RegisterLogRoutes(router *gin.RouterGroup, dockerClient *docker.Client, db *database.Database) {
	logs := router.Group("/logs")
	{
		logs.GET("/crowdsec", handlers.GetCrowdSecLogs(dockerClient))
		logs.GET("/traefik", handlers.GetTraefikLogs(dockerClient, db))
		logs.GET("/traefik/advanced", handlers.AnalyzeTraefikLogsAdvanced(dockerClient))
		logs.GET("/:service", handlers.GetServiceLogs(dockerClient))
		logs.GET("/stream/:service", handlers.StreamLogs(dockerClient))
	}
}

// RegisterBackupRoutes registers backup management routes
func RegisterBackupRoutes(router *gin.RouterGroup, backupMgr *backup.Manager, dockerClient *docker.Client) {
	backupRoutes := router.Group("/backup")
	{
		backupRoutes.GET("/list", handlers.ListBackups(backupMgr))
		backupRoutes.POST("/create", handlers.CreateBackup(backupMgr))
		backupRoutes.POST("/restore", handlers.RestoreBackup(backupMgr))
		backupRoutes.DELETE("/:id", handlers.DeleteBackup(backupMgr))
		backupRoutes.POST("/cleanup", handlers.CleanupOldBackups(backupMgr))
		backupRoutes.GET("/latest", handlers.GetLatestBackup(backupMgr))
	}
}

// RegisterUpdateRoutes registers stack update routes
func RegisterUpdateRoutes(router *gin.RouterGroup, dockerClient *docker.Client) {
	update := router.Group("/update")
	{
		update.GET("/current-tags", handlers.GetCurrentTags(dockerClient))
		update.POST("/with-crowdsec", handlers.UpdateWithCrowdSec(dockerClient))
		update.POST("/without-crowdsec", handlers.UpdateWithoutCrowdSec(dockerClient))
	}
}

// RegisterCronRoutes registers cron job management routes
func RegisterCronRoutes(router *gin.RouterGroup) {
	cron := router.Group("/cron")
	{
		cron.POST("/setup", handlers.SetupCronJob())
		cron.GET("/list", handlers.ListCronJobs())
		cron.DELETE("/:id", handlers.DeleteCronJob())
	}
}

// RegisterAllowlistRoutes registers allowlist management routes
func RegisterAllowlistRoutes(router *gin.RouterGroup, dockerClient *docker.Client) {
	allowlist := router.Group("/allowlist")
	{
		allowlist.GET("/list", handlers.ListAllowlists(dockerClient))
		allowlist.POST("/create", handlers.CreateAllowlist(dockerClient))
		allowlist.GET("/inspect/:name", handlers.InspectAllowlist(dockerClient))
		allowlist.POST("/add", handlers.AddAllowlistEntries(dockerClient))
		allowlist.POST("/remove", handlers.RemoveAllowlistEntries(dockerClient))
		allowlist.DELETE("/:name", handlers.DeleteAllowlist(dockerClient))
	}
}

// RegisterServicesRoutes registers service management routes
func RegisterServicesRoutes(router *gin.RouterGroup, dockerClient *docker.Client, db *database.Database) {
	services := router.Group("/services")
	{
		services.GET("/verify", handlers.VerifyServices(dockerClient))
		services.POST("/shutdown", handlers.GracefulShutdown(dockerClient))
		services.POST("/action", handlers.ServiceAction(dockerClient))
	}

	// CrowdSec specific
	crowdsec := router.Group("/crowdsec")
	{
		crowdsec.GET("/bouncers", handlers.GetBouncers(dockerClient))
		crowdsec.GET("/decisions", handlers.GetDecisions(dockerClient))
		crowdsec.GET("/decisions/analysis", handlers.GetDecisionsAnalysis(dockerClient))
		crowdsec.GET("/alerts/analysis", handlers.GetAlertsAnalysis(dockerClient))
		crowdsec.GET("/metrics", handlers.GetMetrics(dockerClient))
		crowdsec.POST("/enroll", handlers.EnrollCrowdSec(dockerClient))
	}

	// Traefik specific
	traefik := router.Group("/traefik")
	{
		traefik.GET("/integration", handlers.CheckTraefikIntegration(dockerClient, db))
		traefik.GET("/config", handlers.GetTraefikConfig())
		traefik.GET("/config-path", handlers.GetTraefikConfigPath(db))
		traefik.POST("/config-path", handlers.SetTraefikConfigPath(db))
	}

	// Configuration/Settings
	config := router.Group("/config")
	{
		config.GET("/settings", func(c *gin.Context) {
			settings, err := db.GetSettings()
			if err != nil {
				c.JSON(500, gin.H{"error": err.Error()})
				return
			}
			c.JSON(200, gin.H{"success": true, "data": settings})
		})
		config.PUT("/settings", handlers.UpdateSettings(db))
		config.GET("/files/:container/:fileType", handlers.GetFileContent(dockerClient, db))
	}
}
