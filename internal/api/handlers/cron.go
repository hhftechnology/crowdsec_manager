package handlers

import (
	"net/http"

	"crowdsec-manager/internal/cron"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// =============================================================================
// CRON
// =============================================================================

// SetupCronJob sets up a cron job
func SetupCronJob(scheduler *cron.Scheduler) gin.HandlerFunc {
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

		job, err := scheduler.AddJob(req.Schedule, req.Task)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to schedule job: " + err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Cron job setup successfully",
			Data:    job,
		})
	}
}

// ListCronJobs lists all configured cron jobs
func ListCronJobs(scheduler *cron.Scheduler) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Listing cron jobs")

		jobs := scheduler.ListJobs()

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    jobs,
		})
	}
}

// DeleteCronJob deletes a cron job
func DeleteCronJob(scheduler *cron.Scheduler) gin.HandlerFunc {
	return func(c *gin.Context) {
		jobID := c.Param("id")
		logger.Info("Deleting cron job", "id", jobID)

		if err := scheduler.DeleteJob(jobID); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to delete job: " + err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Cron job deleted successfully",
		})
	}
}
