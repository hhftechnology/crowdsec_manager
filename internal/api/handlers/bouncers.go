package handlers

import (
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// GetBouncers retrieves CrowdSec bouncers
func GetBouncers(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec bouncers")

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "bouncers", "list", "-o", "json",
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get bouncers: %v", err),
			})
			return
		}

		// Parse the JSON to ensure it's valid and return as structured data
		var bouncers []models.Bouncer
		if err := json.Unmarshal([]byte(output), &bouncers); err != nil {
			// If JSON parsing fails, log details and return error
			logger.Warn("Failed to parse bouncers JSON",
				"error", err,
				"output_length", len(output),
				"output_preview", truncateString(output, 100))
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse bouncers JSON: %v", err),
			})
			return
		}

		// Compute status for each bouncer
		for i := range bouncers {
			// Primary indicator: if last pull was recent (within 5 minutes), bouncer is connected
			if time.Since(bouncers[i].LastPull) <= 5*time.Minute {
				bouncers[i].Status = "connected"
			} else if bouncers[i].Valid {
				// Last pull is old but key is valid - bouncer exists but inactive
				bouncers[i].Status = "stale"
			} else {
				// Key is invalid - bouncer is disconnected
				bouncers[i].Status = "disconnected"
			}
		}

		logger.Debug("Bouncers API retrieved successfully", "count", len(bouncers))

		// Return properly formatted data
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    bouncers,
		})
	}
}

// AddBouncer adds a new bouncer
func AddBouncer(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Name string `json:"name" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Adding bouncer", "name", req.Name)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "bouncers", "add", req.Name, "-o", "json",
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to add bouncer: %v", err),
			})
			return
		}

		// cscli bouncers add returns the API key as a JSON string or an object depending on version
		// Log output: "72iDIWLzUIm6Bwd2uLh2Pg6mo7FaDl+YV00etlpuyHA"
		var apiKey string
		if err := json.Unmarshal([]byte(output), &apiKey); err == nil {
			// Successfully parsed as string
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Message: "Bouncer added successfully",
				Data: map[string]string{
					"name":    req.Name,
					"api_key": apiKey,
				},
			})
			return
		}

		// Try parsing as array of objects (older versions or different output format)
		var result []map[string]string
		if err := json.Unmarshal([]byte(output), &result); err != nil {
			logger.Error("Failed to parse add bouncer output", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to parse bouncer creation response",
			})
			return
		}

		if len(result) == 0 {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "No bouncer data returned",
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Bouncer added successfully",
			Data:    result[0],
		})
	}
}

// DeleteBouncer deletes a bouncer
func DeleteBouncer(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		if name == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Bouncer name is required",
			})
			return
		}

		logger.Info("Deleting bouncer", "name", name)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "bouncers", "delete", name,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to delete bouncer: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("Bouncer %s deleted successfully", name),
			Data:    gin.H{"output": output},
		})
	}
}
