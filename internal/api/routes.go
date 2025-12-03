package api

import (
	"crowdsec-manager/internal/api/handlers"
	"crowdsec-manager/internal/backup"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/cron"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"

	"github.com/gin-gonic/gin"
)

// RegisterHealthRoutes configures endpoints for system and CrowdSec health monitoring
func RegisterHealthRoutes(router *gin.RouterGroup, dockerClient *docker.Client, db *database.Database, cfg *config.Config) {
	health := router.Group("/health")
	{
		health.GET("/stack", handlers.CheckStackHealth(dockerClient, cfg))
		health.GET("/crowdsec", handlers.CheckCrowdSecHealth(dockerClient, cfg))
		health.GET("/complete", handlers.RunCompleteDiagnostics(dockerClient, db, cfg))
	}
}

// RegisterIPRoutes configures endpoints for IP banning, unbanning, and public IP retrieval
func RegisterIPRoutes(router *gin.RouterGroup, dockerClient *docker.Client, cfg *config.Config) {
	ip := router.Group("/ip")
	{
		ip.GET("/public", handlers.GetPublicIP())
		ip.GET("/blocked/:ip", handlers.IsIPBlocked(dockerClient, cfg))
		ip.GET("/security/:ip", handlers.CheckIPSecurity(dockerClient, cfg))

		ip.POST("/unban", handlers.UnbanIP(dockerClient, cfg))
	}
}

// RegisterWhitelistRoutes configures endpoints for adding IPs to CrowdSec and Traefik whitelists
func RegisterWhitelistRoutes(router *gin.RouterGroup, dockerClient *docker.Client, cfg *config.Config) {
	whitelist := router.Group("/whitelist")
	{
		whitelist.GET("/view", handlers.ViewWhitelist(dockerClient, cfg))
		whitelist.POST("/current", handlers.WhitelistCurrentIP(dockerClient, cfg))
		whitelist.POST("/manual", handlers.WhitelistManualIP(dockerClient, cfg))
		whitelist.POST("/cidr", handlers.WhitelistCIDR(dockerClient, cfg))
		whitelist.POST("/crowdsec", handlers.AddToCrowdSecWhitelist(dockerClient, cfg))
		whitelist.POST("/traefik", handlers.AddToTraefikWhitelist(dockerClient, cfg))
		whitelist.POST("/comprehensive", handlers.SetupComprehensiveWhitelist(dockerClient, cfg))
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

// RegisterCaptchaRoutes configures endpoints for CrowdSec captcha (AppSec) setup and status
func RegisterCaptchaRoutes(router *gin.RouterGroup, dockerClient *docker.Client, db *database.Database, cfg *config.Config) {
	captcha := router.Group("/captcha")
	{
		captcha.POST("/setup", handlers.SetupCaptcha(dockerClient, cfg))
		captcha.GET("/status", handlers.GetCaptchaStatus(dockerClient, db, cfg))
	}
}

// RegisterLogRoutes configures endpoints for viewing container logs and analyzing Traefik access logs
func RegisterLogRoutes(router *gin.RouterGroup, dockerClient *docker.Client, db *database.Database, cfg *config.Config) {
	logs := router.Group("/logs")
	{
		logs.GET("/crowdsec", handlers.GetCrowdSecLogs(dockerClient, cfg))
		logs.GET("/traefik", handlers.GetTraefikLogs(dockerClient, db, cfg))
		logs.GET("/traefik/advanced", handlers.AnalyzeTraefikLogsAdvanced(dockerClient, cfg))
		logs.GET("/:service", handlers.GetServiceLogs(dockerClient))
		logs.GET("/stream/:service", handlers.StreamLogs(dockerClient))
	}
}

// RegisterBackupRoutes configures endpoints for creating, listing, restoring, and managing backups
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

// RegisterUpdateRoutes configures endpoints for checking and applying Docker image updates
func RegisterUpdateRoutes(router *gin.RouterGroup, dockerClient *docker.Client, cfg *config.Config) {
	update := router.Group("/update")
	{
		update.GET("/check", handlers.CheckForUpdates(dockerClient, cfg))
		update.POST("/with-crowdsec", handlers.UpdateWithCrowdSec(dockerClient, cfg))
		update.POST("/without-crowdsec", handlers.UpdateWithoutCrowdSec(dockerClient, cfg))
	}
}

// RegisterServicesRoutes configures endpoints for Docker service management, CrowdSec operations, and Traefik config
func RegisterServicesRoutes(router *gin.RouterGroup, dockerClient *docker.Client, db *database.Database, cfg *config.Config) {
	services := router.Group("/services")
	{
		services.GET("/verify", handlers.VerifyServices(dockerClient, cfg))
		services.POST("/shutdown", handlers.GracefulShutdown(dockerClient, cfg))
		services.POST("/action", handlers.ServiceAction(dockerClient, cfg))

	}

	// CrowdSec specific
	crowdsec := router.Group("/crowdsec")
	{
		crowdsec.GET("/bouncers", handlers.GetBouncers(dockerClient, cfg))
		crowdsec.POST("/bouncers", handlers.AddBouncer(dockerClient, cfg))
		crowdsec.DELETE("/bouncers/:name", handlers.DeleteBouncer(dockerClient, cfg))
		crowdsec.GET("/decisions", handlers.GetDecisions(dockerClient, cfg))
		crowdsec.POST("/decisions", handlers.AddDecision(dockerClient, cfg))
		crowdsec.DELETE("/decisions", handlers.DeleteDecision(dockerClient, cfg))
		crowdsec.POST("/decisions/import", handlers.ImportDecisions(dockerClient, cfg))
		crowdsec.GET("/decisions/analysis", handlers.GetDecisionsAnalysis(dockerClient, cfg))
		crowdsec.GET("/alerts/analysis", handlers.GetAlertsAnalysis(dockerClient, cfg))
		crowdsec.GET("/metrics", handlers.GetMetrics(dockerClient, cfg))
		crowdsec.POST("/enroll", handlers.EnrollCrowdSec(dockerClient, cfg))
		crowdsec.GET("/status", handlers.GetCrowdSecEnrollmentStatus(dockerClient, cfg))
	}

	// Traefik specific
	traefik := router.Group("/traefik")
	{
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

// RegisterNotificationRoutes configures endpoints for Discord webhook notification management
func RegisterNotificationRoutes(router *gin.RouterGroup, dockerClient *docker.Client, db *database.Database, cfg *config.Config) {
	notifications := router.Group("/notifications")
	{
		notifications.GET("/discord", handlers.GetDiscordConfig(db, cfg, dockerClient))
		notifications.POST("/discord", handlers.UpdateDiscordConfig(db, cfg, dockerClient))
	}
}

// RegisterCronRoutes configures endpoints for creating, listing, and deleting scheduled cron jobs
func RegisterCronRoutes(router *gin.RouterGroup, scheduler *cron.Scheduler) {
	cronRoutes := router.Group("/cron")
	{
		cronRoutes.POST("/setup", handlers.SetupCronJob(scheduler))
		cronRoutes.GET("/list", handlers.ListCronJobs(scheduler))
		cronRoutes.DELETE("/:id", handlers.DeleteCronJob(scheduler))
	}
}

// RegisterProfileRoutes configures endpoints for managing profiles.yaml
func RegisterProfileRoutes(router *gin.RouterGroup, db *database.Database, cfg *config.Config, dockerClient *docker.Client) {
	profiles := router.Group("/profiles")
	{
		profiles.GET("", handlers.GetProfiles(cfg))
		profiles.POST("", handlers.UpdateProfiles(db, cfg, dockerClient))
	}
}
