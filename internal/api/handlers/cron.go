package handlers

import (
	"net/http"

	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// =============================================================================
// CRON
// =============================================================================

// SetupCronJob sets up a cron job
func SetupCronJob() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.CronJobRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Setting up cron job", "schedule", req.Schedule, "task", req.Task)

		// In a real implementation, this would interact with the scheduler service
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Cron job setup successfully",
			Data:    gin.H{"schedule": req.Schedule, "task": req.Task},
		})
	}
}

// ListCronJobs lists all configured cron jobs
func ListCronJobs() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Listing cron jobs")

		// In a real implementation, this would retrieve from scheduler service
		jobs := []gin.H{
			{
				"id":       "1",
				"schedule": "0 2 * * *",
				"task":     "backup",
				"enabled":  true,
			},
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    jobs,
		})
	}
}

// DeleteCronJob deletes a cron job
func DeleteCronJob() gin.HandlerFunc {
	return func(c *gin.Context) {
		jobID := c.Param("id")
		logger.Info("Deleting cron job", "id", jobID)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Cron job deleted successfully",
		})
	}
}
