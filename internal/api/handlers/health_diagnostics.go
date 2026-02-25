package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/buger/jsonparser"
)

// parseBouncersJSON parses bouncers JSON output and returns bouncer list with status
func parseBouncersJSON(bouncerOutput string, computeStatus bool) ([]models.Bouncer, error) {
	var bouncers []models.Bouncer
	dataBytes := []byte(bouncerOutput)

	_, err := jsonparser.ArrayEach(dataBytes, func(value []byte, dataType jsonparser.ValueType, offset int, parseErr error) {
		var bouncer models.Bouncer

		if name, err := jsonparser.GetString(value, "name"); err == nil {
			bouncer.Name = name
		}
		if ipAddr, err := jsonparser.GetString(value, "ip_address"); err == nil {
			bouncer.IPAddress = ipAddr
		}
		if valid, err := jsonparser.GetBoolean(value, "valid"); err == nil {
			bouncer.Valid = valid
		}
		if lastPull, err := jsonparser.GetString(value, "last_pull"); err == nil {
			if t, err := time.Parse(time.RFC3339, lastPull); err == nil {
				bouncer.LastPull = t
			}
		}
		if bouncerType, err := jsonparser.GetString(value, "type"); err == nil {
			bouncer.Type = bouncerType
		}
		if version, err := jsonparser.GetString(value, "version"); err == nil {
			bouncer.Version = version
		}

		if computeStatus {
			if bouncer.Valid && time.Since(bouncer.LastPull) <= 60*time.Minute {
				bouncer.Status = "connected"
			} else if bouncer.Valid {
				bouncer.Status = "stale"
			} else {
				bouncer.Status = "disconnected"
			}
		}

		bouncers = append(bouncers, bouncer)
	})

	return bouncers, err
}

// checkBouncersHealth retrieves and checks bouncer health, returning a HealthCheckItem
func checkBouncersHealth(dockerClient *docker.Client, containerName string) models.HealthCheckItem {
	bouncersOutput, err := dockerClient.ExecCommand(containerName, []string{
		"cscli", "bouncers", "list", "-o", "json",
	})
	if err != nil {
		return models.HealthCheckItem{
			Status:  "degraded",
			Message: "Unable to retrieve bouncers list",
			Error:   fmt.Sprintf("%v", err),
		}
	}

	if bouncersOutput == "null" || bouncersOutput == "" || bouncersOutput == "[]" {
		return models.HealthCheckItem{
			Status:  "healthy",
			Message: "No bouncers registered",
			Details: "Active: 0, Total: 0",
		}
	}

	bouncers, err := parseBouncersJSON(bouncersOutput, false)
	if err != nil {
		return models.HealthCheckItem{
			Status:  "degraded",
			Message: "Failed to parse bouncers data",
			Error:   fmt.Sprintf("%v", err),
		}
	}

	activeBouncers := 0
	for _, b := range bouncers {
		if b.Valid && time.Since(b.LastPull) <= 60*time.Minute {
			activeBouncers++
		}
	}

	return models.HealthCheckItem{
		Status:  "healthy",
		Message: fmt.Sprintf("%d active bouncer(s) out of %d total", activeBouncers, len(bouncers)),
		Details: fmt.Sprintf("Active: %d, Total: %d", activeBouncers, len(bouncers)),
	}
}

// checkMetricsHealth retrieves and checks metrics health, returning a HealthCheckItem
func checkMetricsHealth(dockerClient *docker.Client, containerName string, metricsURL string) models.HealthCheckItem {
	metricsOutput, err := dockerClient.ExecCommand(containerName, []string{
		"cscli", "metrics", "-o", "json", "--url", metricsURL,
	})
	if err != nil {
		return models.HealthCheckItem{
			Status:  "unhealthy",
			Message: "Metrics endpoint not accessible",
			Error:   fmt.Sprintf("%v", err),
		}
	}

	var metricsData map[string]interface{}
	if err := json.Unmarshal([]byte(metricsOutput), &metricsData); err == nil {
		return models.HealthCheckItem{
			Status:  "healthy",
			Message: "Metrics endpoint is accessible",
			Metrics: metricsData,
		}
	}

	return models.HealthCheckItem{
		Status:  "healthy",
		Message: "Metrics endpoint is accessible (raw output)",
		Details: truncateString(metricsOutput, 200),
	}
}

// collectContainerHealth collects health status for all stack containers
func collectContainerHealth(dockerClient *docker.Client, cfg *config.Config) ([]models.Container, bool) {
	containerNames := []string{cfg.CrowdsecContainerName, cfg.TraefikContainerName, cfg.PangolinContainerName, cfg.GerbilContainerName}
	var containers []models.Container
	allRunning := true

	for _, name := range containerNames {
		containerID, err := dockerClient.GetContainerID(name)
		if err != nil {
			containers = append(containers, models.Container{
				Name:    name,
				Status:  "not found",
				Running: false,
			})
			allRunning = false
			continue
		}

		isRunning, _ := dockerClient.IsContainerRunning(name)
		status := "stopped"
		if isRunning {
			status = "running"
		} else {
			allRunning = false
		}

		containers = append(containers, models.Container{
			Name:    name,
			ID:      containerID,
			Status:  status,
			Running: isRunning,
		})
	}

	return containers, allRunning
}

// parseDiagnosticDecisions parses decisions from cscli output for diagnostics
func parseDiagnosticDecisions(decisionOutput string) []models.Decision {
	var decisions []models.Decision

	var rawDecisions []map[string]interface{}
	if err := json.Unmarshal([]byte(decisionOutput), &rawDecisions); err != nil {
		logger.Warn("Failed to parse decisions JSON",
			"error", err,
			"output_length", len(decisionOutput),
			"output_preview", truncateString(decisionOutput, 100))
		return decisions
	}

	decisions = make([]models.Decision, 0, len(rawDecisions))
	for _, raw := range rawDecisions {
		decision := models.Decision{
			ID:       int64(getInt(raw, "id")),
			Duration: getString(raw, "duration"),
		}

		decision.Source = getString(raw, "source")
		if decision.Source == "" {
			decision.Source = getString(raw, "origin")
		}
		decision.Origin = decision.Source

		decision.Type = getString(raw, "type")
		decision.Scope = getString(raw, "scope")
		decision.Value = getString(raw, "value")

		decision.Scenario = getString(raw, "scenario")
		if decision.Scenario == "" {
			decision.Scenario = getString(raw, "reason")
		}
		decision.Reason = decision.Scenario

		decision.CreatedAt = getString(raw, "created_at")

		decisions = append(decisions, decision)
	}

	return decisions
}

// checkTraefikIntegrationDiagnostic checks Traefik integration for diagnostics
func checkTraefikIntegrationDiagnostic(dockerClient *docker.Client, db *database.Database, cfg *config.Config) *models.TraefikIntegration {
	traefikIntegration := &models.TraefikIntegration{
		MiddlewareConfigured: false,
		ConfigFiles:          []string{},
		LapiKeyFound:         false,
		AppsecEnabled:        false,
	}

	configPaths := []string{
		cfg.TraefikDynamicConfig,
		cfg.TraefikStaticConfig,
	}

	if db != nil {
		if path, err := db.GetTraefikDynamicConfigPath(); err == nil {
			configPaths = append([]string{path}, configPaths...)
		}
	}

	var configContent string
	var foundConfigPath string

	for _, path := range configPaths {
		output, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{"cat", path})
		if err == nil && output != "" {
			configContent = output
			foundConfigPath = path
			break
		}
	}

	if configContent != "" {
		traefikIntegration.MiddlewareConfigured = true
		traefikIntegration.ConfigFiles = append(traefikIntegration.ConfigFiles, foundConfigPath)

		configLower := strings.ToLower(configContent)

		if strings.Contains(configLower, "crowdsec-bouncer-traefik-plugin") ||
			strings.Contains(configLower, "crowdseclapikey") ||
			strings.Contains(configLower, "crowdsec") {
			traefikIntegration.LapiKeyFound = true
		}

		if strings.Contains(configLower, "appsec") {
			traefikIntegration.AppsecEnabled = true
		}
	}

	return traefikIntegration
}
