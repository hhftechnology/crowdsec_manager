package handlers

import (
	"fmt"
	"net/http"
	"time"

	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/buger/jsonparser"
	"github.com/gin-gonic/gin"
)

// =============================================================================
// ALLOWLIST MANAGEMENT
// =============================================================================

// ListAllowlists lists all CrowdSec allowlists
func ListAllowlists(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Listing allowlists")

		output, err := dockerClient.ExecCommand("crowdsec", []string{"cscli", "allowlists", "list", "-o", "json"})
		if err != nil {
			logger.Error("Failed to list allowlists", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to list allowlists: %v", err),
			})
			return
		}

		// Log the raw output for debugging
		logger.Info("Allowlists list output", "output", output)

		var allowlists []models.Allowlist
		if err := json.Unmarshal([]byte(output), &allowlists); err != nil {
			// If output is empty or "null", it means no allowlists
			if output == "null" || output == "" {
				c.JSON(http.StatusOK, models.Response{
					Success: true,
					Data:    gin.H{"allowlists": []models.Allowlist{}, "count": 0},
					Message: "No allowlists found",
				})
				return
			}

			logger.Error("Failed to parse allowlists JSON", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse allowlists: %v", err),
			})
			return
		}


	// Compute Size field from Items length for each allowlist
	for i := range allowlists {
		allowlists[i].Size = len(allowlists[i].Items)
	}
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"allowlists": allowlists, "count": len(allowlists)},
			Message: fmt.Sprintf("Found %d allowlists", len(allowlists)),
		})
	}
}

// CreateAllowlist creates a new CrowdSec allowlist
func CreateAllowlist(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.AllowlistCreateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Invalid request: %v", err),
			})
			return
		}

		logger.Info("Creating allowlist", "name", req.Name)

		cmd := []string{"cscli", "allowlists", "create", req.Name, "--description", req.Description}
		output, err := dockerClient.ExecCommand("crowdsec", cmd)
		if err != nil {
			logger.Error("Failed to create allowlist", "name", req.Name, "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to create allowlist: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: models.Allowlist{
				Name:        req.Name,
				Description: req.Description,
				CreatedAt:   time.Now().Format(time.RFC3339),
			},
			Message: fmt.Sprintf("Allowlist '%s' created successfully", req.Name),
		})
	}
}

// InspectAllowlist inspects a specific allowlist
func InspectAllowlist(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		logger.Info("Inspecting allowlist", "name", name)

		output, err := dockerClient.ExecCommand("crowdsec", []string{"cscli", "allowlists", "inspect", name, "-o", "json"})
		if err != nil {
			logger.Error("Failed to inspect allowlist", "name", name, "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to inspect allowlist: %v", err),
			})
			return
		}

		var response models.AllowlistInspectResponse
		if err := json.Unmarshal([]byte(output), &response); err != nil {
			logger.Error("Failed to parse allowlist JSON", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse allowlist data: %v", err),
			})
			return
		}

		// Calculate count from items length (CrowdSec doesn't provide it directly in top level sometimes)
		response.Count = len(response.Items)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    response,
			Message: fmt.Sprintf("Allowlist '%s' has %d entries", name, response.Count),
		})
	}
}

// AddAllowlistEntries adds entries to an allowlist
func AddAllowlistEntries(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.AllowlistAddEntriesRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Invalid request: %v", err),
			})
			return
		}

		logger.Info("Adding entries to allowlist", "name", req.AllowlistName, "count", len(req.Values))

		// Build command
		cmd := []string{"cscli", "allowlists", "add", req.AllowlistName}
		cmd = append(cmd, req.Values...)

		// Add optional flags
		if req.Expiration != "" {
			cmd = append(cmd, "-e", req.Expiration)
		}
		if req.Description != "" {
			cmd = append(cmd, "-d", req.Description)
		}

		output, err := dockerClient.ExecCommand("crowdsec", cmd)
		if err != nil {
			logger.Error("Failed to add entries to allowlist", "name", req.AllowlistName, "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to add entries: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("Added %d entries to allowlist '%s'", len(req.Values), req.AllowlistName),
		})
	}
}

// RemoveAllowlistEntries removes entries from an allowlist
func RemoveAllowlistEntries(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.AllowlistRemoveEntriesRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Invalid request: %v", err),
			})
			return
		}

		logger.Info("Removing entries from allowlist", "name", req.AllowlistName, "count", len(req.Values))

		cmd := []string{"cscli", "allowlists", "remove", req.AllowlistName}
		cmd = append(cmd, req.Values...)

		output, err := dockerClient.ExecCommand("crowdsec", cmd)
		if err != nil {
			logger.Error("Failed to remove entries from allowlist", "name", req.AllowlistName, "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to remove entries: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("Removed %d entries from allowlist '%s'", len(req.Values), req.AllowlistName),
		})
	}
}

// DeleteAllowlist deletes an allowlist
func DeleteAllowlist(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		logger.Info("Deleting allowlist", "name", name)

		output, err := dockerClient.ExecCommand("crowdsec", []string{"cscli", "allowlists", "delete", name})
		if err != nil {
			logger.Error("Failed to delete allowlist", "name", name, "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to delete allowlist: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("Allowlist '%s' deleted successfully", name),
		})
	}
}

