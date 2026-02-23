package handlers

import (
	"fmt"
	"net/http"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// AddDecisionRequest represents the payload for adding a decision
type AddDecisionRequest struct {
	IP       string `json:"ip"`
	Range    string `json:"range"`
	Duration string `json:"duration"`
	Type     string `json:"type"`
	Scope    string `json:"scope"`
	Value    string `json:"value"`
	Reason   string `json:"reason"`
}

// AddDecision adds a new decision via cscli
func AddDecision(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		var req AddDecisionRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request body: " + err.Error(),
			})
			return
		}

		cmd := []string{"cscli", "decisions", "add"}

		// Helper to add flag if value is present
		addFlag := func(flag, value string) {
			if value != "" {
				cmd = append(cmd, flag, value)
			}
		}

		addFlag("--ip", req.IP)
		addFlag("--range", req.Range)
		addFlag("--duration", req.Duration)
		addFlag("--type", req.Type)
		addFlag("--scope", req.Scope)
		addFlag("--value", req.Value)
		addFlag("--reason", req.Reason)

		logger.Info("Adding decision", "command", cmd)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to add decision", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to add decision: %v. Output: %s", err, output),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Decision added successfully",
			Data:    gin.H{"output": output},
		})
	}
}

// DeleteDecision deletes a decision via cscli
func DeleteDecision(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		type DeleteDecisionRequest struct {
			ID       string `form:"id" json:"id"`
			IP       string `form:"ip" json:"ip"`
			Range    string `form:"range" json:"range"`
			Type     string `form:"type" json:"type"`
			Scope    string `form:"scope" json:"scope"`
			Value    string `form:"value" json:"value"`
			Scenario string `form:"scenario" json:"scenario"`
			Origin   string `form:"origin" json:"origin"`
		}

		var req DeleteDecisionRequest
		if err := c.ShouldBind(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request parameters: " + err.Error(),
			})
			return
		}

		cmd := []string{"cscli", "decisions", "delete"}
		hasFilter := false

		addFlag := func(flag, value string) {
			if value != "" {
				cmd = append(cmd, flag, value)
				hasFilter = true
			}
		}

		addFlag("--id", req.ID)
		addFlag("--ip", req.IP)
		addFlag("--range", req.Range)
		addFlag("--type", req.Type)
		addFlag("--scope", req.Scope)
		addFlag("--value", req.Value)
		addFlag("--scenario", req.Scenario)
		addFlag("--origin", req.Origin)

		if !hasFilter {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "At least one filter (id, ip, range, etc.) must be provided to delete decisions",
			})
			return
		}

		logger.Info("Deleting decision", "command", cmd)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to delete decision", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to delete decision: %v. Output: %s", err, output),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Decision(s) deleted successfully",
			Data:    gin.H{"output": output},
		})
	}
}
