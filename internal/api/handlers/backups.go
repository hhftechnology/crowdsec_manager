package handlers

import (
	"fmt"
	"net/http"

	"crowdsec-manager/internal/backup"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// =============================================================================
// BACKUP
// =============================================================================

// ListBackups lists all available backups
func ListBackups(backupMgr *backup.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Listing backups")

		backups, err := backupMgr.List()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to list backups: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    backups,
		})
	}
}

// CreateBackup creates a new backup
func CreateBackup(backupMgr *backup.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.BackupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Creating backup", "dryRun", req.DryRun)

		backup, err := backupMgr.Create(req.DryRun)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to create backup: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Backup created successfully",
			Data:    backup,
		})
	}
}

// RestoreBackup restores from a backup
func RestoreBackup(backupMgr *backup.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.RestoreRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		if !req.Confirm {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Restore must be confirmed",
			})
			return
		}

		logger.Info("Restoring backup", "backupID", req.BackupID)

		if err := backupMgr.Restore(req.BackupID); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to restore backup: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Backup restored successfully",
		})
	}
}

// DeleteBackup deletes a specific backup
func DeleteBackup(backupMgr *backup.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		backupID := c.Param("id")
		logger.Info("Deleting backup", "backupID", backupID)

		if err := backupMgr.Delete(backupID); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to delete backup: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Backup deleted successfully",
		})
	}
}

// CleanupOldBackups removes old backups based on retention policy
func CleanupOldBackups(backupMgr *backup.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Cleaning up old backups")

		if err := backupMgr.CleanupOld(); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to cleanup backups: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Old backups cleaned up successfully",
		})
	}
}

// GetLatestBackup gets the most recent backup
func GetLatestBackup(backupMgr *backup.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting latest backup")

		backup, err := backupMgr.FindLatest()
		if err != nil {
			c.JSON(http.StatusNotFound, models.Response{
				Success: false,
				Error:   "No backups found",
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    backup,
		})
	}
}
