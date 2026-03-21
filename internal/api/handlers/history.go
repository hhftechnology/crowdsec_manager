package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

func parseStaleFilter(raw string) (*bool, error) {
	if raw == "" {
		return nil, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

// GetHistoryConfig returns history retention config.
func GetHistoryConfig() gin.HandlerFunc {
	return func(c *gin.Context) {
		if historyService == nil {
			c.JSON(http.StatusServiceUnavailable, models.Response{Success: false, Error: "history service unavailable"})
			return
		}

		cfg, err := historyService.GetHistoryConfig(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: "failed to read history config: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, models.Response{Success: true, Data: cfg})
	}
}

// UpdateHistoryConfig updates history retention config.
func UpdateHistoryConfig() gin.HandlerFunc {
	return func(c *gin.Context) {
		if historyService == nil {
			c.JSON(http.StatusServiceUnavailable, models.Response{Success: false, Error: "history service unavailable"})
			return
		}

		var req struct {
			RetentionDays int `json:"retention_days"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "invalid request: " + err.Error()})
			return
		}

		if req.RetentionDays < 1 || req.RetentionDays > 365 {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "retention_days must be between 1 and 365"})
			return
		}

		cfg, err := historyService.UpdateRetentionDays(c.Request.Context(), req.RetentionDays)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: "failed to update history config: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, models.Response{Success: true, Message: "History config updated", Data: cfg})
	}
}

// GetDecisionHistory returns persisted decision history entries.
func GetDecisionHistory() gin.HandlerFunc {
	return func(c *gin.Context) {
		if historyService == nil {
			c.JSON(http.StatusServiceUnavailable, models.Response{Success: false, Error: "history service unavailable"})
			return
		}

		stale, err := parseStaleFilter(c.Query("stale"))
		if err != nil {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "invalid stale filter"})
			return
		}

		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
		filter := models.DecisionHistoryFilter{
			Stale:    stale,
			Value:    c.Query("value"),
			Scenario: c.Query("scenario"),
			Since:    c.Query("since"),
			Limit:    limit,
			Offset:   offset,
		}

		records, total, err := historyService.ListDecisionHistory(c.Request.Context(), filter)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: "failed to load decision history: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: gin.H{
				"decisions": records,
				"count":     len(records),
				"total":     total,
			},
		})
	}
}

// GetAlertHistory returns persisted alert history entries.
func GetAlertHistory() gin.HandlerFunc {
	return func(c *gin.Context) {
		if historyService == nil {
			c.JSON(http.StatusServiceUnavailable, models.Response{Success: false, Error: "history service unavailable"})
			return
		}

		stale, err := parseStaleFilter(c.Query("stale"))
		if err != nil {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "invalid stale filter"})
			return
		}

		limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
		offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
		filter := models.AlertHistoryFilter{
			Stale:    stale,
			Value:    c.Query("value"),
			Scenario: c.Query("scenario"),
			Since:    c.Query("since"),
			Limit:    limit,
			Offset:   offset,
		}

		records, total, err := historyService.ListAlertHistory(c.Request.Context(), filter)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: "failed to load alert history: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: gin.H{
				"alerts": records,
				"count":  len(records),
				"total":  total,
			},
		})
	}
}

// GetRepeatedOffenders returns repeated offenders from persisted history.
func GetRepeatedOffenders() gin.HandlerFunc {
	return func(c *gin.Context) {
		if historyService == nil {
			c.JSON(http.StatusServiceUnavailable, models.Response{Success: false, Error: "history service unavailable"})
			return
		}

		offenders, err := historyService.ListRepeatedOffenders(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: "failed to load repeated offenders: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: gin.H{
				"offenders": offenders,
				"count":     len(offenders),
			},
		})
	}
}

// GetHistoryStats returns aggregate counts for the history dashboard.
func GetHistoryStats() gin.HandlerFunc {
	return func(c *gin.Context) {
		if historyService == nil {
			c.JSON(http.StatusServiceUnavailable, models.Response{Success: false, Error: "history service unavailable"})
			return
		}

		stats, err := historyService.GetHistoryStats(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: "failed to load history stats: " + err.Error()})
			return
		}

		c.JSON(http.StatusOK, models.Response{Success: true, Data: stats})
	}
}

// ReapplyDecision re-inserts a historical decision into CrowdSec as a new ban or captcha.
func ReapplyDecision(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		if historyService == nil {
			c.JSON(http.StatusServiceUnavailable, models.Response{Success: false, Error: "history service unavailable"})
			return
		}
		dockerClient = resolveDockerClient(c, dockerClient)

		var req models.ReapplyDecisionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "invalid request: " + err.Error()})
			return
		}
		if req.ID <= 0 {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "id is required"})
			return
		}
		if req.Type == "" {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "type is required"})
			return
		}
		if req.Duration == "" {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "duration is required"})
			return
		}

		record, err := historyService.GetDecisionHistoryRecord(c.Request.Context(), req.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: "failed to load history record: " + err.Error()})
			return
		}
		if record == nil {
			c.JSON(http.StatusNotFound, models.Response{Success: false, Error: fmt.Sprintf("history record %d not found", req.ID)})
			return
		}

		cmd := buildReapplyCmd(record.Scope, record.Value, req.Type, req.Duration, req.Reason)
		logger.Info("Reapplying decision from history", "id", req.ID, "value", record.Value, "type", req.Type)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to reapply decision", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("failed to reapply decision: %v. Output: %s", err, output),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{Success: true, Message: "Decision reapplied successfully"})
	}
}

// BulkReapplyDecisions re-inserts multiple historical decisions into CrowdSec.
func BulkReapplyDecisions(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		if historyService == nil {
			c.JSON(http.StatusServiceUnavailable, models.Response{Success: false, Error: "history service unavailable"})
			return
		}
		dockerClient = resolveDockerClient(c, dockerClient)

		var req models.BulkReapplyDecisionsRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "invalid request: " + err.Error()})
			return
		}
		if len(req.IDs) == 0 {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "ids must not be empty"})
			return
		}
		if len(req.IDs) > 100 {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "maximum 100 ids per request"})
			return
		}
		if req.Type == "" {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "type is required"})
			return
		}
		if req.Duration == "" {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "duration is required"})
			return
		}

		result := models.BulkReapplyResult{}
		ctx := c.Request.Context()

		for _, id := range req.IDs {
			record, err := historyService.GetDecisionHistoryRecord(ctx, id)
			if err != nil {
				result.Failed++
				result.Errors = append(result.Errors, fmt.Sprintf("id %d: fetch failed: %v", id, err))
				continue
			}
			if record == nil {
				result.Failed++
				result.Errors = append(result.Errors, fmt.Sprintf("id %d: not found", id))
				continue
			}

			cmd := buildReapplyCmd(record.Scope, record.Value, req.Type, req.Duration, req.Reason)
			if _, execErr := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd); execErr != nil {
				result.Failed++
				result.Errors = append(result.Errors, fmt.Sprintf("id %d (%s): %v", id, record.Value, execErr))
			} else {
				result.Succeeded++
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("Reapplied %d of %d decisions", result.Succeeded, len(req.IDs)),
			Data:    result,
		})
	}
}

// buildReapplyCmd constructs the cscli decisions add command for reapplication.
// Uses --ip for Ip scope, --scope/--value otherwise.
func buildReapplyCmd(scope, value, decisionType, duration, reason string) []string {
	cmd := []string{"cscli", "decisions", "add", "--type", decisionType, "--duration", duration}
	if strings.EqualFold(scope, "Ip") || scope == "" {
		cmd = append(cmd, "--ip", value)
	} else {
		cmd = append(cmd, "--scope", scope, "--value", value)
	}
	if reason != "" {
		cmd = append(cmd, "--reason", reason)
	}
	return cmd
}
