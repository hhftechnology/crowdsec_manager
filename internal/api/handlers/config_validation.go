package handlers

import (
	"net/http"

	"crowdsec-manager/internal/configvalidator"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// ValidateConfigs runs full config validation and returns the report
func ValidateConfigs(validator *configvalidator.Validator) gin.HandlerFunc {
	return func(c *gin.Context) {
		report := validator.ValidateAll()
		c.JSON(http.StatusOK, models.Response{Success: true, Data: report})
	}
}

// GetConfigSnapshots returns all stored config snapshots
func GetConfigSnapshots(validator *configvalidator.Validator) gin.HandlerFunc {
	return func(c *gin.Context) {
		snapshots, err := validator.GetSnapshots()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, models.Response{Success: true, Data: snapshots})
	}
}

// SnapshotAllConfigs forces a snapshot of all current configs
func SnapshotAllConfigs(validator *configvalidator.Validator) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := validator.SnapshotAll(); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, models.Response{Success: true, Message: "All configs snapshotted"})
	}
}

// RestoreConfig restores a specific config from the stored snapshot
func RestoreConfig(validator *configvalidator.Validator) gin.HandlerFunc {
	return func(c *gin.Context) {
		configType := c.Param("type")
		if configType == "" {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "config type is required"})
			return
		}

		if err := validator.RestoreConfig(configType); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, models.Response{Success: true, Message: "Config restored: " + configType})
	}
}

// DeleteConfigSnapshot removes a stored snapshot for a config type
func DeleteConfigSnapshot(validator *configvalidator.Validator) gin.HandlerFunc {
	return func(c *gin.Context) {
		configType := c.Param("type")
		if configType == "" {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "config type is required"})
			return
		}

		if err := validator.DeleteSnapshot(configType); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, models.Response{Success: true, Message: "Snapshot deleted: " + configType})
	}
}

// AcceptCurrentConfig re-snapshots the current live value, resolving drift
func AcceptCurrentConfig(validator *configvalidator.Validator) gin.HandlerFunc {
	return func(c *gin.Context) {
		configType := c.Param("type")
		if configType == "" {
			c.JSON(http.StatusBadRequest, models.Response{Success: false, Error: "config type is required"})
			return
		}

		if err := validator.SnapshotConfigByType(configType, "manual"); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{Success: false, Error: err.Error()})
			return
		}
		c.JSON(http.StatusOK, models.Response{Success: true, Message: "Current config accepted as new baseline: " + configType})
	}
}
