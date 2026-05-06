package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"crowdsec-manager/internal/cache"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/constants"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/buger/jsonparser"
	"github.com/gin-gonic/gin"
)

// GetDecisionsAnalysis retrieves CrowdSec decisions with advanced filtering
func GetDecisionsAnalysis(dockerClient *docker.Client, cfg *config.Config, ttlCache ...*cache.TTLCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		cacheKey := crowdSecAnalysisCacheKey(c, "decisions")
		if cacheStore := optionalCache(ttlCache); cacheStore != nil {
			if cached, ok := cacheStore.Get(cacheKey); ok {
				c.JSON(http.StatusOK, models.Response{
					Success: true,
					Data:    cached,
				})
				return
			}
		}

		logger.Info("Getting CrowdSec decisions analysis via cscli")

		defaultLimit := config.EffectiveLimit(cfg.DecisionListLimit, constants.MaxListLimit)
		limit, offset := parsePaginationParams(c, defaultLimit, constants.MaxListLimit)
		fetchLimit := defaultLimit
		if c.Query("limit") != "" || c.Query("offset") != "" {
			fetchLimit = constants.MaxListLimit
		}

		cmd := []string{"cscli", "decisions", "list", "-o", "json", "--limit", strconv.Itoa(fetchLimit)}

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
			result := gin.H{"decisions": []models.Decision{}, "count": 0, "total": 0, "limit": limit, "offset": offset}
			if cacheStore := optionalCache(ttlCache); cacheStore != nil {
				cacheStore.Set(cacheKey, result, analysisCacheTTL)
			}
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    result,
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

		total := len(decisions)
		pagedDecisions := paginateDecisions(decisions, limit, offset)
		result := gin.H{
			"decisions": pagedDecisions,
			"count":     len(pagedDecisions),
			"total":     total,
			"limit":     limit,
			"offset":    offset,
		}
		if cacheStore := optionalCache(ttlCache); cacheStore != nil {
			cacheStore.Set(cacheKey, result, analysisCacheTTL)
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    result,
		})
	}
}

// GetAlertsAnalysis retrieves CrowdSec alerts with advanced filtering.
func GetAlertsAnalysis(dockerClient *docker.Client, cfg *config.Config, ttlCache ...*cache.TTLCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		handler := getAlertsAnalysisWithExecutor(alertAnalysisHandlerInput{
			Executor: resolveDockerClient(c, dockerClient),
			Config:   cfg,
			Cache:    optionalCache(ttlCache),
		})
		handler(c)
	}
}

type alertAnalysisHandlerInput struct {
	Executor cscliExecutor
	Config   *config.Config
	Cache    *cache.TTLCache
}

func getAlertsAnalysisWithExecutor(input alertAnalysisHandlerInput) gin.HandlerFunc {
	return func(c *gin.Context) {
		cacheKey := crowdSecAnalysisCacheKey(c, "alerts")
		if input.Cache != nil {
			if cached, ok := input.Cache.Get(cacheKey); ok {
				c.JSON(http.StatusOK, models.Response{
					Success: true,
					Data:    cached,
				})
				return
			}
		}

		logger.Info("Getting CrowdSec alerts analysis via cscli")

		cmd := buildAlertsAnalysisCommand(c, input.Config)
		output, err := input.Executor.ExecCommand(input.Config.CrowdsecContainerName, cmd)
		if err != nil {
			logger.Error("Failed to get alerts analysis", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get alerts: %v", err),
			})
			return
		}

		alerts, err := parseAlertsAnalysisOutput(output)
		if err != nil {
			logger.Warn("Failed to parse alerts analysis output", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse alerts: %v", err),
			})
			return
		}

		logger.Info("Alerts analysis retrieved successfully", "count", len(alerts))
		writeAlertsAnalysisResult(alertAnalysisResultInput{
			Context:         c,
			Cache:           input.Cache,
			CacheKey:        cacheKey,
			LastNonEmptyKey: alertLastNonEmptyAnalysisCacheKey(c),
			Alerts:          alerts,
		})
	}
}

func buildAlertsAnalysisCommand(c *gin.Context, cfg *config.Config) []string {
	if v := c.Query("id"); v != "" {
		return []string{"cscli", "alerts", "inspect", v, "-o", "json"}
	}

	alertLimit := config.EffectiveLimit(cfg.AlertListLimit, constants.MaxListLimit)
	cmd := []string{"cscli", "alerts", "list", "-o", "json", "--limit", strconv.Itoa(alertLimit)}

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

	return cmd
}

func parseAlertsAnalysisOutput(output string) ([]interface{}, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" || trimmed == "null" {
		return []interface{}{}, nil
	}

	dataBytes, parseErr := parseCLIJSONToBytes(output)
	if parseErr != nil {
		return nil, fmt.Errorf("normalize alerts JSON: %w", parseErr)
	}

	var alerts []interface{}
	if err := json.Unmarshal(dataBytes, &alerts); err != nil {
		var singleAlert interface{}
		if errSingle := json.Unmarshal(dataBytes, &singleAlert); errSingle != nil {
			return nil, fmt.Errorf("parse alerts JSON: %w", err)
		}
		if singleAlert == nil {
			return []interface{}{}, nil
		}
		alerts = []interface{}{singleAlert}
	}

	normalizeAlertsAnalysis(alerts)
	return alerts, nil
}

func normalizeAlertsAnalysis(alerts []interface{}) {
	for _, item := range alerts {
		node, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if src, ok := node["source"].(map[string]interface{}); ok {
			node["value"] = src["value"]
			node["scope"] = src["scope"]
		}
		if decs, ok := node["decisions"].([]interface{}); ok && len(decs) > 0 {
			if d, ok := decs[0].(map[string]interface{}); ok {
				node["origin"] = d["origin"]
				node["type"] = d["type"]
			}
		}
	}
}

type alertAnalysisResultInput struct {
	Context         *gin.Context
	Cache           *cache.TTLCache
	CacheKey        string
	LastNonEmptyKey string
	Alerts          []interface{}
}

func writeAlertsAnalysisResult(input alertAnalysisResultInput) {
	result := gin.H{"alerts": input.Alerts, "count": len(input.Alerts)}
	if input.Cache != nil {
		if len(input.Alerts) > 0 {
			input.Cache.Set(input.CacheKey, result, analysisCacheTTL)
			input.Cache.Set(input.LastNonEmptyKey, result, alertLastNonEmptyAnalysisCacheTTL)
			input.Context.JSON(http.StatusOK, models.Response{Success: true, Data: result})
			return
		}
		if cached, ok := input.Cache.Get(input.LastNonEmptyKey); ok {
			input.Cache.Set(input.CacheKey, cached, emptyAnalysisCacheTTL)
			input.Context.JSON(http.StatusOK, models.Response{Success: true, Data: cached})
			return
		}
		input.Cache.Set(input.CacheKey, result, emptyAnalysisCacheTTL)
	}

	input.Context.JSON(http.StatusOK, models.Response{Success: true, Data: result})
}
