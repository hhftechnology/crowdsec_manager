package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"crowdsec-manager/internal/cache"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/buger/jsonparser"
	"github.com/gin-gonic/gin"
)

// GetDecisionsAnalysis retrieves CrowdSec decisions with advanced filtering
func GetDecisionsAnalysis(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		logger.Info("Getting CrowdSec decisions analysis via cscli")

		cmd := []string{"cscli", "decisions", "list", "-o", "json"}

		// Add filters based on query parameters
		if v := c.Query("ip"); v != "" {
			cmd = append(cmd, "--ip", v)
		}
		if v := c.Query("range"); v != "" {
			cmd = append(cmd, "--range", v)
		}
		if v := c.Query("type"); v != "" && v != "all" {
			cmd = append(cmd, "--type", v)
		}
		if v := c.Query("scope"); v != "" && v != "all" {
			cmd = append(cmd, "--scope", v)
		}
		if v := c.Query("value"); v != "" {
			cmd = append(cmd, "--value", v)
		}
		if v := c.Query("scenario"); v != "" {
			cmd = append(cmd, "--scenario", v)
		}
		if v := c.Query("origin"); v != "" && v != "all" {
			cmd = append(cmd, "--origin", v)
		}
		if v := c.Query("until"); v != "" {
			cmd = append(cmd, "--until", v)
		}
		if v := c.Query("includeAll"); v == "true" {
			cmd = append(cmd, "-a")
		}

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get decisions analysis: %v", err),
			})
			return
		}

		// Check if output is empty or null
		if output == "null" || output == "" || output == "[]" {
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    gin.H{"decisions": []models.Decision{}, "count": 0},
			})
			return
		}

		// Parse alerts using normalized CLI JSON output.
		var decisions []models.Decision
		dataBytes, parseErr := parseCLIJSONToBytes(output)
		if parseErr != nil {
			logger.Error("Failed to normalize decisions analysis JSON", "error", parseErr, "output_preview", truncateString(output, 200))
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse decisions JSON: %v", parseErr),
			})
			return
		}

		_, err = jsonparser.ArrayEach(dataBytes, func(alertValue []byte, alertType jsonparser.ValueType, alertOffset int, alertErr error) {
			// Get alert's created_at for fallback
			var alertCreatedAt string
			if createdAt, err := jsonparser.GetString(alertValue, "created_at"); err == nil {
				alertCreatedAt = createdAt
			}

			// Get alert's ID
			var alertID int64
			if id, err := jsonparser.GetInt(alertValue, "id"); err == nil {
				alertID = id
			}

			// Parse decisions array within this alert
			foundNested := false
			jsonparser.ArrayEach(alertValue, func(decisionValue []byte, decisionType jsonparser.ValueType, decisionOffset int, decisionErr error) {
				foundNested = true
				decision := parseDecisionNode(decisionValue)
				if decision.CreatedAt == "" {
					decision.CreatedAt = alertCreatedAt
				}
				decision.AlertID = alertID
				decisions = append(decisions, decision)
			}, "decisions")

			// Fallback: if no nested decisions found, check if the top-level
			// item itself has decision fields (manual decisions via cscli decisions add)
			if !foundNested {
				if _, _, _, err := jsonparser.Get(alertValue, "type"); err == nil {
					decision := parseDecisionNode(alertValue)
					if decision.CreatedAt == "" {
						decision.CreatedAt = alertCreatedAt
					}
					decision.AlertID = alertID
					decisions = append(decisions, decision)
				}
			}
		})

		if err != nil {
			logger.Error("Failed to parse decisions analysis JSON", "error", err, "output_preview", truncateString(output, 200))
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse decisions JSON: %v", err),
			})
			return
		}

		logger.Info("Decisions analysis retrieved successfully",
			"count", len(decisions),
			"cmd", cmd)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"decisions": decisions, "count": len(decisions)},
		})
	}
}

// GetAlertsAnalysis retrieves CrowdSec alerts with advanced filtering
func GetAlertsAnalysis(dockerClient *docker.Client, cfg *config.Config, ttlCache ...*cache.TTLCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)

		// Cache key includes the "since" param to differentiate dashboard vs analysis queries
		cacheKey := "alerts-analysis-" + c.Query("since")
		if len(ttlCache) > 0 && ttlCache[0] != nil {
			if cached, ok := ttlCache[0].Get(cacheKey); ok {
				c.JSON(http.StatusOK, models.Response{
					Success: true,
					Data:    cached,
				})
				return
			}
		}

		logger.Info("Getting CrowdSec alerts analysis via cscli")

		var cmd []string
		if v := c.Query("id"); v != "" {
			cmd = []string{"cscli", "alerts", "inspect", v, "-o", "json"}
		} else {
			cmd = []string{"cscli", "alerts", "list", "-o", "json"}

			// Add filters based on query parameters
			if v := c.Query("ip"); v != "" {
				cmd = append(cmd, "--ip", v)
			}
			if v := c.Query("range"); v != "" {
				cmd = append(cmd, "--range", v)
			}
			if v := c.Query("type"); v != "" && v != "all" {
				cmd = append(cmd, "--type", v)
			}
			if v := c.Query("scope"); v != "" && v != "all" {
				cmd = append(cmd, "--scope", v)
			}
			if v := c.Query("value"); v != "" {
				cmd = append(cmd, "--value", v)
			}
			if v := c.Query("scenario"); v != "" {
				cmd = append(cmd, "--scenario", v)
			}
			if v := c.Query("origin"); v != "" && v != "all" {
				cmd = append(cmd, "--origin", v)
			}
			if v := c.Query("since"); v != "" {
				cmd = append(cmd, "--since", v)
			}
			if v := c.Query("until"); v != "" {
				cmd = append(cmd, "--until", v)
			}
			if v := c.Query("includeAll"); v == "true" {
				cmd = append(cmd, "-a")
			}
		}

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to get alerts analysis", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get alerts: %v", err),
			})
			return
		}

		// Parse JSON
		dataBytes, parseErr := parseCLIJSONToBytes(output)
		if parseErr != nil {
			if output == "null" || output == "" {
				c.JSON(http.StatusOK, models.Response{
					Success: true,
					Data:    gin.H{"alerts": []interface{}{}, "count": 0},
				})
				return
			}
			logger.Warn("Failed to normalize alerts JSON", "error", parseErr)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse alerts: %v", parseErr),
			})
			return
		}
		var alerts []interface{}
		if err := json.Unmarshal(dataBytes, &alerts); err != nil {
			// If unmarshaling as list fails, try as a single object (behavior for inspect command)
			var singleAlert interface{}
			if errSingle := json.Unmarshal(dataBytes, &singleAlert); errSingle == nil {
				alerts = []interface{}{singleAlert}
			} else {
				if output == "null" || output == "" {
					c.JSON(http.StatusOK, models.Response{
						Success: true,
						Data:    gin.H{"alerts": []interface{}{}, "count": 0},
					})
					return
				}

				logger.Warn("Failed to parse alerts JSON", "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Failed to parse alerts: %v", err),
				})
				return
			}
		}

		logger.Info("Alerts analysis retrieved successfully", "count", len(alerts))

		result := gin.H{"alerts": alerts, "count": len(alerts)}
		if len(ttlCache) > 0 && ttlCache[0] != nil {
			ttlCache[0].Set(cacheKey, result, 30*time.Second)
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    result,
		})
	}
}
