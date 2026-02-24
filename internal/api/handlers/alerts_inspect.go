package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// numericIDPattern validates that an alert ID contains only digits.
var numericIDPattern = regexp.MustCompile(`^\d+$`)

// InspectAlert returns detailed alert info including events
func InspectAlert(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		alertID := c.Param("id")
		if alertID == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Alert ID is required",
			})
			return
		}

		// Validate alertID is numeric to prevent command injection
		if !numericIDPattern.MatchString(alertID) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Alert ID must be numeric",
			})
			return
		}

		cmd := []string{"cscli", "alerts", "inspect", alertID, "-o", "json"}
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to inspect alert", "alertID", alertID, "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to inspect alert %s: %v", alertID, err),
			})
			return
		}

		if output == "" || output == "null" {
			c.JSON(http.StatusNotFound, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Alert %s not found", alertID),
			})
			return
		}

		// Parse the JSON output
		var alertData interface{}
		if err := json.Unmarshal([]byte(output), &alertData); err != nil {
			logger.Warn("Failed to parse alert inspect JSON", "alertID", alertID, "error", err)
			// Return raw output if parsing fails
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    output,
				Message: fmt.Sprintf("Alert %s details (raw format)", alertID),
			})
			return
		}

		logger.Info("Alert inspected successfully", "alertID", alertID)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    alertData,
			Message: fmt.Sprintf("Alert %s details retrieved", alertID),
		})
	}
}
