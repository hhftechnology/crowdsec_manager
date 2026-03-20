package handlers

import (
	"net/http"
	"strconv"

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
