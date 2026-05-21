package handlers

import (
	"fmt"
	"net/http"

	"crowdsec-manager/internal/cache"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

type logProcessingRequest struct {
	Enabled *bool `json:"enabled"`
}

// GetLogProcessing returns whether Traefik/CrowdSec log processing is enabled.
func GetLogProcessing(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		enabled, err := logProcessingEnabled(db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("failed to read log processing setting: %v", err)})
			return
		}
		c.JSON(http.StatusOK, models.Response{Success: true, Data: gin.H{"enabled": enabled}})
	}
}

// UpdateLogProcessing updates the global Traefik/CrowdSec log processing switch.
func UpdateLogProcessing(db *database.Database, ttlCache ...*cache.TTLCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req logProcessingRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid request: " + err.Error()})
			return
		}
		if req.Enabled == nil {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "Invalid request: enabled is required"})
			return
		}
		enabled := *req.Enabled

		settings, err := db.GetSettings()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("failed to read settings: %v", err)})
			return
		}

		settings.LogProcessingEnabled = enabled
		if err := db.UpdateSettings(settings); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("failed to update log processing setting: %v", err)})
			return
		}

		if !enabled {
			invalidateServiceDashboardCache(ttlCache...)
		}

		c.JSON(http.StatusOK, models.Response{Success: true, Message: "Log processing setting updated", Data: gin.H{"enabled": enabled}})
	}
}

func logProcessingEnabled(db *database.Database) (bool, error) {
	if db == nil {
		return true, nil
	}
	settings, err := db.GetSettings()
	if err != nil {
		return false, err
	}
	return settings.LogProcessingEnabled, nil
}

func requireLogProcessingEnabled(c *gin.Context, db *database.Database) bool {
	enabled, err := logProcessingEnabled(db)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: fmt.Sprintf("failed to read log processing setting: %v", err)})
		return false
	}
	if !enabled {
		c.JSON(http.StatusConflict, models.Response{Success: false, Error: "log processing is disabled"})
		return false
	}
	return true
}

func invalidateServiceDashboardCache(ttlCache ...*cache.TTLCache) {
	c := optionalCache(ttlCache)
	if c == nil {
		return
	}
	c.DeletePrefix(serviceDashboardCachePrefix)
}
