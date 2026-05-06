package handlers

import (
	"net/http"
	"strconv"

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
	Origin   string `json:"origin"`
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

		// Validate that at least one selector is present and IP/range are not both set.
		if err := ValidateAddDecisionRequest(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   err.Error(),
			})
			return
		}

		// Normalize duration: "permanent", "", "0" → "" (omit flag); "30d" → "720h"; invalid → 400.
		normalized, ok := NormalizeDuration(req.Duration)
		if !ok {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "invalid duration: " + req.Duration,
			})
			return
		}

		cmd := []string{"cscli", "decisions", "add"}
		cmd, _ = appendCLIFlags(cmd, []CLIFlag{
			{"--ip", req.IP},
			{"--range", req.Range},
			{"--duration", normalized},
			{"--type", req.Type},
			{"--scope", req.Scope},
			{"--value", req.Value},
			{"--reason", req.Reason},
			{"--origin", req.Origin},
		})

		logger.Info("Adding decision", "command", cmd)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to add decision", "error", err, "output", output)
			details := output
			if details == "" {
				details = err.Error()
			}
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to add decision",
				Details: details,
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

		// Reject when both IP and Range are supplied — they are mutually exclusive in cscli.
		if req.IP != "" && req.Range != "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   ErrIPAndRange.Error(),
			})
			return
		}

		cmd := []string{"cscli", "decisions", "delete"}
		var count int
		cmd, count = appendCLIFlags(cmd, []CLIFlag{
			{"--id", req.ID},
			{"--ip", req.IP},
			{"--range", req.Range},
			{"--type", req.Type},
			{"--scope", req.Scope},
			{"--value", req.Value},
			{"--scenario", req.Scenario},
			{"--origin", req.Origin},
		})

		if count == 0 {
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
			details := output
			if details == "" {
				details = err.Error()
			}
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to delete decision",
				Details: details,
			})
			return
		}

		if historyService != nil {
			decisionID, _ := strconv.ParseInt(req.ID, 10, 64)
			if err := historyService.MarkDecisionDeleted(c.Request.Context(), decisionID, req.Value); err != nil {
				logger.Warn("Failed to mark decision history stale after delete", "id", req.ID, "value", req.Value, "error", err)
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Decision(s) deleted successfully",
			Data:    gin.H{"output": output},
		})
	}
}
