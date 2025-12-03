package handlers

import (
	"fmt"
	"net/http"
	"time"

	"crowdsec-manager/internal/config"
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
func ListAllowlists(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Listing allowlists")

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "allowlists", "list", "-o", "json"})
		if err != nil {
			logger.Error("Failed to list allowlists", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to list allowlists: %v", err),
			})
			return
		}

		// Check if output is empty or null
		if output == "null" || output == "" || output == "[]" {
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    gin.H{"allowlists": []models.Allowlist{}, "count": 0},
				Message: "No allowlists found",
			})
			return
		}

		// Parse allowlists using jsonparser
		var allowlists []models.Allowlist
		dataBytes := []byte(output)

		_, err = jsonparser.ArrayEach(dataBytes, func(value []byte, dataType jsonparser.ValueType, offset int, err error) {
			var allowlist models.Allowlist

			// Extract fields
			if name, err := jsonparser.GetString(value, "name"); err == nil {
				allowlist.Name = name
			}
			if desc, err := jsonparser.GetString(value, "description"); err == nil {
				allowlist.Description = desc
			}
			if createdAt, err := jsonparser.GetString(value, "created_at"); err == nil {
				allowlist.CreatedAt = createdAt
			}
			if updatedAt, err := jsonparser.GetString(value, "updated_at"); err == nil {
				allowlist.UpdatedAt = updatedAt
			}

			// Parse items array
			var items []models.AllowlistEntry
			jsonparser.ArrayEach(value, func(itemValue []byte, itemType jsonparser.ValueType, itemOffset int, itemErr error) {
				var entry models.AllowlistEntry

				if val, err := jsonparser.GetString(itemValue, "value"); err == nil {
					entry.Value = val
				}
				if exp, err := jsonparser.GetString(itemValue, "expiration"); err == nil {
					entry.Expiration = exp
				}
				if createdAt, err := jsonparser.GetString(itemValue, "created_at"); err == nil {
					// Parse time
					if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
						entry.CreatedAt = t
					}
				}

				items = append(items, entry)
			}, "items")

			allowlist.Items = items
			allowlist.Size = len(items)

			allowlists = append(allowlists, allowlist)
		})

		if err != nil {
			logger.Error("Failed to parse allowlists JSON", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse allowlists: %v", err),
			})
			return
		}

		logger.Debug("Allowlists retrieved successfully", "count", len(allowlists))

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"allowlists": allowlists, "count": len(allowlists)},
			Message: fmt.Sprintf("Found %d allowlists", len(allowlists)),
		})
	}
}


// CreateAllowlist creates a new CrowdSec allowlist
func CreateAllowlist(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
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
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
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
func InspectAllowlist(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		logger.Info("Inspecting allowlist", "name", name)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "allowlists", "inspect", name, "-o", "json"})
		if err != nil {
			logger.Error("Failed to inspect allowlist", "name", name, "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to inspect allowlist: %v", err),
			})
			return
		}

		// Parse response using jsonparser
		dataBytes := []byte(output)
		var response models.AllowlistInspectResponse

		// Extract top-level fields
		if n, err := jsonparser.GetString(dataBytes, "name"); err == nil {
			response.Name = n
		}
		if desc, err := jsonparser.GetString(dataBytes, "description"); err == nil {
			response.Description = desc
		}
		if createdAt, err := jsonparser.GetString(dataBytes, "created_at"); err == nil {
			if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
				response.CreatedAt = t.Format(time.RFC3339)
			} else {
				response.CreatedAt = createdAt
			}
		}
		if updatedAt, err := jsonparser.GetString(dataBytes, "updated_at"); err == nil {
			if t, err := time.Parse(time.RFC3339, updatedAt); err == nil {
				response.UpdatedAt = t.Format(time.RFC3339)
			} else {
				response.UpdatedAt = updatedAt
			}
		}

		// Parse items array
		var items []models.AllowlistEntry
		jsonparser.ArrayEach(dataBytes, func(itemValue []byte, itemType jsonparser.ValueType, itemOffset int, itemErr error) {
			var entry models.AllowlistEntry

			if val, err := jsonparser.GetString(itemValue, "value"); err == nil {
				entry.Value = val
			}
			if exp, err := jsonparser.GetString(itemValue, "expiration"); err == nil {
				entry.Expiration = exp
			}
			if createdAt, err := jsonparser.GetString(itemValue, "created_at"); err == nil {
				if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
					entry.CreatedAt = t
				}
			}

			items = append(items, entry)
		}, "items")

		response.Items = items
		response.Count = len(items)

		logger.Debug("Allowlist inspected successfully", "name", name, "count", response.Count)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    response,
			Message: fmt.Sprintf("Allowlist '%s' has %d entries", name, response.Count),
		})
	}
}


// AddAllowlistEntries adds entries to an allowlist
func AddAllowlistEntries(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
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

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
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
func RemoveAllowlistEntries(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
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

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
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
func DeleteAllowlist(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		logger.Info("Deleting allowlist", "name", name)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "allowlists", "delete", name})
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

