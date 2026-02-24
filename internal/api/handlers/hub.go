package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// allowedHubTypes defines the valid CrowdSec hub item types.
// Used for input validation to prevent command injection.
var allowedHubTypes = map[string]bool{
	"scenarios":     true,
	"parsers":       true,
	"collections":   true,
	"postoverflows": true,
}

// validateHubType checks that the given type is one of the allowed hub item types.
func validateHubType(t string) bool {
	return allowedHubTypes[t]
}

// validateHubItemName checks that the hub item name looks reasonable
// (author/name format, no shell metacharacters).
func validateHubItemName(name string) bool {
	if name == "" {
		return false
	}
	// Must not contain shell metacharacters
	for _, ch := range name {
		if ch == ';' || ch == '&' || ch == '|' || ch == '$' || ch == '`' ||
			ch == '(' || ch == ')' || ch == '{' || ch == '}' || ch == '<' ||
			ch == '>' || ch == '\'' || ch == '"' || ch == '\\' || ch == '\n' ||
			ch == '\r' || ch == ' ' || ch == '\t' {
			return false
		}
	}
	return true
}

// ListHubItems lists all hub items (scenarios, parsers, collections, postoverflows)
func ListHubItems(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		cmd := []string{"cscli", "hub", "list", "-o", "json"}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to list hub items", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to list hub items: %v", err),
			})
			return
		}

		// Try to parse as structured JSON
		var parsed interface{}
		if err := json.Unmarshal([]byte(output), &parsed); err != nil {
			logger.Warn("Failed to parse hub list JSON, returning raw", "error", err)
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    output,
				Message: "Hub items retrieved (raw format)",
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    parsed,
			Message: "Hub items retrieved successfully",
		})
	}
}

// InstallHubItem installs a hub item by type and name
func InstallHubItem(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		var req models.HubActionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		req.Type = strings.TrimSpace(strings.ToLower(req.Type))
		req.Name = strings.TrimSpace(req.Name)

		if !validateHubType(req.Type) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Invalid hub type: %s. Must be one of: scenarios, parsers, collections, postoverflows", req.Type),
			})
			return
		}

		if !validateHubItemName(req.Name) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid hub item name",
			})
			return
		}

		cmd := []string{"cscli", req.Type, "install", req.Name, "-o", "json"}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to install hub item", "type", req.Type, "name", req.Name, "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to install %s/%s: %v", req.Type, req.Name, err),
			})
			return
		}

		logger.Info("Hub item installed", "type", req.Type, "name", req.Name)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    output,
			Message: fmt.Sprintf("Successfully installed %s: %s", req.Type, req.Name),
		})
	}
}

// RemoveHubItem removes a hub item by type and name
func RemoveHubItem(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		var req models.HubActionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		req.Type = strings.TrimSpace(strings.ToLower(req.Type))
		req.Name = strings.TrimSpace(req.Name)

		if !validateHubType(req.Type) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Invalid hub type: %s. Must be one of: scenarios, parsers, collections, postoverflows", req.Type),
			})
			return
		}

		if !validateHubItemName(req.Name) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid hub item name",
			})
			return
		}

		cmd := []string{"cscli", req.Type, "remove", req.Name, "-o", "json"}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to remove hub item", "type", req.Type, "name", req.Name, "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to remove %s/%s: %v", req.Type, req.Name, err),
			})
			return
		}

		logger.Info("Hub item removed", "type", req.Type, "name", req.Name)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    output,
			Message: fmt.Sprintf("Successfully removed %s: %s", req.Type, req.Name),
		})
	}
}

// UpgradeAllHub upgrades all hub items
func UpgradeAllHub(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		cmd := []string{"cscli", "hub", "upgrade", "-o", "json"}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to upgrade hub items", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to upgrade hub items: %v", err),
			})
			return
		}

		logger.Info("Hub items upgraded successfully")

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    output,
			Message: "Hub items upgraded successfully",
		})
	}
}
