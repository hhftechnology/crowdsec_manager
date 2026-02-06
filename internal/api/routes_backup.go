package api

import (
	"crowdsec-manager/internal/api/handlers"

	"github.com/gin-gonic/gin"
)

// registerBackupRoutes configures endpoints for creating, listing, restoring, and managing backups.
func registerBackupRoutes(router *gin.RouterGroup, deps *Dependencies) {
	backupRoutes := router.Group("/backup")
	{
		backupRoutes.GET("/list", handlers.ListBackups(deps.BackupManager))
		backupRoutes.POST("/create", handlers.CreateBackup(deps.BackupManager))
		backupRoutes.POST("/restore", handlers.RestoreBackup(deps.BackupManager))
		backupRoutes.DELETE("/:id", handlers.DeleteBackup(deps.BackupManager))
		backupRoutes.POST("/cleanup", handlers.CleanupOldBackups(deps.BackupManager))
		backupRoutes.GET("/latest", handlers.GetLatestBackup(deps.BackupManager))
	}
}
