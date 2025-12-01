package handlers

import (
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
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
			Data:    gin.H{"bouncers": bouncers, "count": len(bouncers)},
		})
	}
}

// AddBouncer adds a new bouncer with a generated API key
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

		// Generate unique API key (32 bytes = 43 characters in base64 URL encoding)
		apiKey, err := generateBouncerAPIKey()
		if err != nil {
			logger.Error("Failed to generate API key", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to generate API key: %v", err),
			})
			return
		}

		logger.Debug("Generated API key for bouncer", "name", req.Name, "key_length", len(apiKey))

		// Add bouncer with the generated key
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "bouncers", "add", req.Name, "--key", apiKey,
		})
		if err != nil {
			logger.Error("Failed to add bouncer", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to add bouncer: %v", err),
			})
			return
		}

		logger.Info("Bouncer added successfully", "name", req.Name)

		// Return the bouncer info with the generated API key
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("Bouncer '%s' added successfully. Save the API key - it won't be shown again!", req.Name),
			Data: gin.H{
				"name":    req.Name,
				"api_key": apiKey,
			},
		})
	}
}

// generateBouncerAPIKey generates a cryptographically secure random API key
// The key is 32 bytes encoded as base64 URL-safe string (43 characters)
func generateBouncerAPIKey() (string, error) {
	// Generate 32 random bytes (256 bits)
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode as base64 URL-safe string (no padding)
	apiKey := base64.RawURLEncoding.EncodeToString(randomBytes)
	return apiKey, nil
}

// DeleteBouncer deletes a bouncer
func DeleteBouncer(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := strings.TrimSpace(c.Param("name"))
		if name == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Bouncer name is required",
			})
			return
		}

		logger.Info("Deleting bouncer", "name", name)

		// Execute delete command
		cmd := []string{"cscli", "bouncers", "delete", name}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		
		// Log the output for debugging
		logger.Info("Delete command executed", "cmd", cmd, "output", output, "error", err)

		if err != nil {
			logger.Error("Failed to delete bouncer", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to delete bouncer: %v. Output: %s", err, output),
			})
			return
		}

		// Verify deletion by checking if bouncer still exists
		// We list bouncers and check if the name is still there
		checkCmd := []string{"cscli", "bouncers", "list", "-o", "json"}
		checkOutput, checkErr := dockerClient.ExecCommand(cfg.CrowdsecContainerName, checkCmd)
		if checkErr == nil {
			var bouncers []models.Bouncer
			if jsonErr := json.Unmarshal([]byte(checkOutput), &bouncers); jsonErr == nil {
				for _, b := range bouncers {
					if b.Name == name {
						// Bouncer still exists!
						logger.Warn("Bouncer still exists after deletion", "name", name)
						c.JSON(http.StatusInternalServerError, models.Response{
							Success: false,
							Error:   fmt.Sprintf("Bouncer deletion appeared to succeed but bouncer '%s' is still present. Please try again.", name),
						})
						return
					}
				}
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("Bouncer %s deleted successfully", name),
			Data:    gin.H{"output": output},
		})
	}
}
