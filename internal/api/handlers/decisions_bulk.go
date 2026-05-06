package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// BulkDeleteResult reports the outcome of a bulk delete operation.
// SuccessCount and FailureCount always sum to the number of requested IDs.
// The response is always HTTP 200 — partial failures are reported in the body.
type BulkDeleteResult struct {
	SuccessCount int                  `json:"success_count"`
	FailureCount int                  `json:"failure_count"`
	Deleted      []int64              `json:"deleted"`
	Failed       []BulkDeleteFailure  `json:"failed"`
}

// BulkDeleteFailure holds the id and error message for one failed deletion.
type BulkDeleteFailure struct {
	ID    int64  `json:"id"`
	Error string `json:"error"`
}

// cscliExecutor is a minimal interface for executing cscli commands.
// *docker.Client satisfies this interface; tests inject fakeDockerClient.
type cscliExecutor interface {
	ExecCommand(containerName string, cmd []string) (string, error)
}

// BulkDeleteDecisions deletes multiple decisions by ID in a single request.
// It accepts *docker.Client (which satisfies cscliExecutor) via the interface
// so tests can inject a fake without a real Docker daemon.
//
// POST /crowdsec/decisions/bulk-delete
// Body: {"ids": [12, 34, 56]}
// Response: always 200 with {success_count, failure_count, deleted, failed}
func BulkDeleteDecisions(executor cscliExecutor, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			IDs []int64 `json:"ids"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request body: " + err.Error(),
			})
			return
		}
		if len(req.IDs) == 0 {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "ids must not be empty",
			})
			return
		}

		result := BulkDeleteResult{
			Deleted: make([]int64, 0, len(req.IDs)),
			Failed:  make([]BulkDeleteFailure, 0),
		}
		ctx := c.Request.Context()

		for _, id := range req.IDs {
			idStr := strconv.FormatInt(id, 10)
			cmd := []string{"cscli", "decisions", "delete", "--id", idStr}
			logger.Info("Bulk deleting decision", "id", id)

			output, err := executor.ExecCommand(cfg.CrowdsecContainerName, cmd)
			if err != nil {
				errMsg := output
				if errMsg == "" {
					errMsg = err.Error()
				}
				result.FailureCount++
				result.Failed = append(result.Failed, BulkDeleteFailure{
					ID:    id,
					Error: errMsg,
				})
				logger.Error("Failed to bulk delete decision", "id", id, "error", err)
				continue
			}

			result.SuccessCount++
			result.Deleted = append(result.Deleted, id)

			// Mirror the history mark from DeleteDecision for each successfully deleted id.
			if historyService != nil {
				if markErr := historyService.MarkDecisionDeleted(ctx, id, ""); markErr != nil {
					logger.Warn("Failed to mark decision history stale after bulk delete", "id", id, "error", markErr)
				}
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("Deleted %d of %d decisions", result.SuccessCount, len(req.IDs)),
			Data:    result,
		})
	}
}
