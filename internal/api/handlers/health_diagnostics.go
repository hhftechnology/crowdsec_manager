package handlers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/traefikconfig"

	"github.com/buger/jsonparser"
)

// parseBouncersJSON parses bouncers JSON output and returns bouncer list with status
func parseBouncersJSON(bouncerOutput string, computeStatus bool) ([]models.Bouncer, error) {
	var bouncers []models.Bouncer
	dataBytes, err := parseCLIJSONToBytes(bouncerOutput)
	if err != nil {
		return bouncers, err
	}

	_, err = jsonparser.ArrayEach(dataBytes, func(value []byte, dataType jsonparser.ValueType, offset int, parseErr error) {
		var bouncer models.Bouncer

		if name, err := jsonparser.GetString(value, "name"); err == nil {
			bouncer.Name = name
		}
		if ipAddr, err := jsonparser.GetString(value, "ip_address"); err == nil {
			bouncer.IPAddress = ipAddr
		}
		// Parse timestamps with multiple format support
		parseTime := func(key string) time.Time {
			if s, err := jsonparser.GetString(value, key); err == nil {
				for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
					if t, err := time.Parse(layout, s); err == nil {
						return t
					}
				}
			}
			return time.Time{}
		}

		bouncer.LastPull = parseTime("last_pull")
		bouncer.CreatedAt = parseTime("created_at")
		bouncer.UpdatedAt = parseTime("updated_at")

		if bouncerType, err := jsonparser.GetString(value, "type"); err == nil {
			bouncer.Type = bouncerType
		}
		if version, err := jsonparser.GetString(value, "version"); err == nil {
			bouncer.Version = version
		}

		// A bouncer that exists in the list is valid by definition.
		// CrowdSec deletes revoked bouncers rather than marking them,
		// so the "revoked" and legacy "valid" fields are not reliable
		// indicators of actual connectivity (confirmed by CrowdSec team, see #47).
		bouncer.Valid = true

		if computeStatus {
			lastActivity := bouncer.LastActivity()

			if !lastActivity.IsZero() && time.Since(lastActivity) <= 5*time.Minute {
				bouncer.Status = "connected"
			} else if lastActivity.IsZero() {
				bouncer.Status = "registered" // enrolled but never pulled
			} else if time.Since(lastActivity) <= 60*time.Minute {
				bouncer.Status = "connected"
			} else {
				bouncer.Status = "stale"
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
		lastActivity := b.LastActivity()
		if !lastActivity.IsZero() && time.Since(lastActivity) <= 60*time.Minute {
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
	if dataBytes, parseErr := parseCLIJSONToBytes(metricsOutput); parseErr == nil && json.Unmarshal(dataBytes, &metricsData) == nil {
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

// checkTraefikIntegrationDiagnostic checks Traefik integration for diagnostics
func checkTraefikIntegrationDiagnostic(dockerClient *docker.Client, db *database.Database, cfg *config.Config) *models.TraefikIntegration {
	traefikIntegration := &models.TraefikIntegration{
		MiddlewareConfigured: false,
		ConfigFiles:          []string{},
		LapiKeyFound:         false,
		AppsecEnabled:        false,
	}

	dynamicConfigPath := cfg.TraefikDynamicConfig
	if db != nil {
		if path, err := db.GetTraefikDynamicConfigPath(); err == nil {
			dynamicConfigPath = path
		}
	}

	var configContent string
	var foundConfigPaths []string

	if result, err := traefikconfig.ReadContainer(dockerClient, cfg.TraefikContainerName, dynamicConfigPath); err == nil && result.Content != "" {
		configContent = result.Content
		foundConfigPaths = append(foundConfigPaths, result.SourcePaths...)
	} else if output, err := dockerClient.ReadFileFromContainer(cfg.TraefikContainerName, cfg.TraefikStaticConfig); err == nil && output != "" {
		configContent = output
		foundConfigPaths = append(foundConfigPaths, cfg.TraefikStaticConfig)
	}

	if configContent != "" {
		traefikIntegration.MiddlewareConfigured = true
		traefikIntegration.ConfigFiles = append(traefikIntegration.ConfigFiles, foundConfigPaths...)

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
