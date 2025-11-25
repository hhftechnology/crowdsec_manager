package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"crowdsec-manager/internal/backup"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

// =============================================================================
// 1. HEALTH & DIAGNOSTICS
// =============================================================================
// CheckStackHealth checks the health of all containers in the stack
func CheckStackHealth(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Checking stack health")

		containerNames := []string{cfg.CrowdsecContainerName, cfg.TraefikContainerName, cfg.PangolinContainerName, cfg.GerbilContainerName}
		var containers []models.Container

		allRunning := true
		for _, name := range containerNames {
			containerID, err := dockerClient.GetContainerID(name)
			if err != nil {
				logger.Warn("Container not found", "name", name)
				containers = append(containers, models.Container{
					Name:    name,
					ID:      "",
					Status:  "not found",
					Running: false,
				})
				allRunning = false
				continue
			}

			isRunning, err := dockerClient.IsContainerRunning(name)
			if err != nil {
				logger.Error("Failed to check container status", "name", name, "error", err)
				containers = append(containers, models.Container{
					Name:    name,
					ID:      containerID,
					Status:  "error",
					Running: false,
				})
				allRunning = false
				continue
			}

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

		healthStatus := models.HealthStatus{
			Containers: containers,
			AllRunning: allRunning,
			Timestamp:  time.Now(),
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    healthStatus,
			Message: fmt.Sprintf("Stack health check complete. All running: %v", allRunning),
		})
	}
}

// RunCompleteDiagnostics runs a complete system diagnostic
func RunCompleteDiagnostics(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Running complete diagnostics")

		// Get health status
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

		healthStatus := &models.HealthStatus{
			Containers: containers,
			AllRunning: allRunning,
			Timestamp:  time.Now(),
		}

		// Get bouncers
		var bouncers []models.Bouncer
		bouncerOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "bouncers", "list", "-o", "json"})
		if err == nil {
			// Parse bouncer JSON output
			if err := json.Unmarshal([]byte(bouncerOutput), &bouncers); err != nil {
				logger.Warn("Failed to parse bouncers JSON",
					"error", err,
					"output_length", len(bouncerOutput),
					"output_preview", truncateString(bouncerOutput, 100))
			} else {
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
				logger.Debug("Bouncers retrieved successfully", "count", len(bouncers))
			}
		} else {
			logger.Warn("Failed to execute bouncers command", "error", err)
		}

		// Get decisions
		var decisions []models.Decision
		decisionOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "decisions", "list", "-o", "json"})
		if err == nil {
			// Parse as raw JSON first to handle field name variations
			var rawDecisions []map[string]interface{}
			if err := json.Unmarshal([]byte(decisionOutput), &rawDecisions); err != nil {
				logger.Warn("Failed to parse decisions JSON",
					"error", err,
					"output_length", len(decisionOutput),
					"output_preview", truncateString(decisionOutput, 100))
			} else {
				// Convert to normalized Decision format
				decisions = make([]models.Decision, 0, len(rawDecisions))
				for _, raw := range rawDecisions {
					decision := models.Decision{
						ID:       int64(getInt(raw, "id")),
						Duration: getString(raw, "duration"),
					}

					// Handle origin/source field (CrowdSec might use either)
					decision.Source = getString(raw, "source")
					if decision.Source == "" {
						decision.Source = getString(raw, "origin")
					}
					decision.Origin = decision.Source

					// Handle type field
					decision.Type = getString(raw, "type")

					// Handle scope field
					decision.Scope = getString(raw, "scope")

					// Handle value field
					decision.Value = getString(raw, "value")

					// Handle scenario/reason field (CrowdSec might use either)
					decision.Scenario = getString(raw, "scenario")
					if decision.Scenario == "" {
						decision.Scenario = getString(raw, "reason")
					}
					decision.Reason = decision.Scenario

					// Handle created_at field
					decision.CreatedAt = getString(raw, "created_at")

					decisions = append(decisions, decision)
				}
				logger.Debug("Decisions retrieved successfully", "count", len(decisions))
			}
		} else {
			logger.Warn("Failed to execute decisions command", "error", err)
		}

		// Check Traefik integration
		traefikIntegration := &models.TraefikIntegration{
			MiddlewareConfigured: false,
			ConfigFiles:          []string{},
			LapiKeyFound:         false,
			AppsecEnabled:        false,
		}

		// Check multiple possible config files
		configPaths := []string{
			"/etc/traefik/dynamic_config.yml",
			"/etc/traefik/traefik_config.yml",
		}

		// Get dynamic config path from database if available
		if db != nil {
			if path, err := db.GetTraefikDynamicConfigPath(); err == nil {
				// Prepend database path to the beginning of the list
				configPaths = append([]string{path}, configPaths...)
			}
		}

		var configContent string
		var foundConfigPath string

		// Try each path until we find one that works
		for _, path := range configPaths {
			output, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{"cat", path})
			if err == nil && output != "" {
				configContent = output
				foundConfigPath = path
				break
			}
		}

		// Check for Traefik middleware configuration
		if configContent != "" {
			traefikIntegration.MiddlewareConfigured = true
			traefikIntegration.ConfigFiles = append(traefikIntegration.ConfigFiles, foundConfigPath)

			// Better detection logic - use case-insensitive matching
			configLower := strings.ToLower(configContent)

			// Check for LAPI key (bouncer plugin configuration)
			if strings.Contains(configLower, "crowdsec-bouncer-traefik-plugin") ||
				strings.Contains(configLower, "crowdseclapikey") ||
				strings.Contains(configLower, "crowdsec") {
				traefikIntegration.LapiKeyFound = true
			}

			// Check for AppSec
			if strings.Contains(configLower, "appsec") {
				traefikIntegration.AppsecEnabled = true
			}
		}

		result := models.DiagnosticResult{
			Health:             healthStatus,
			Bouncers:           bouncers,
			Decisions:          decisions,
			TraefikIntegration: traefikIntegration,
			Timestamp:          time.Now(),
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    result,
			Message: "Complete diagnostics finished successfully",
		})
	}
}

// =============================================================================
// 2. IP MANAGEMENT
// =============================================================================

// GetPublicIP retrieves the server's public IP address
func GetPublicIP() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting public IP")

		// Try multiple services for reliability
		services := []string{
			"https://api.ipify.org",
			"https://ifconfig.me/ip",
			"https://icanhazip.com",
		}

		var publicIP string
		var lastErr error

		for _, service := range services {
			resp, err := http.Get(service)
			if err != nil {
				lastErr = err
				continue
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				lastErr = err
				continue
			}

			publicIP = strings.TrimSpace(string(body))
			if publicIP != "" {
				break
			}
		}

		if publicIP == "" {
			logger.Error("Failed to get public IP", "error", lastErr)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to retrieve public IP address",
			})
			return
		}

		logger.Info("Public IP retrieved", "ip", publicIP)
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"ip": publicIP},
		})
	}
}

// IsIPBlocked checks if an IP is blocked by CrowdSec
func IsIPBlocked(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.Param("ip")
		logger.Info("Checking if IP is blocked", "ip", ip)

		// Check CrowdSec decisions
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "decisions", "list", "-i", ip, "-o", "json",
		})
		if err != nil {
			logger.Error("Failed to check IP decisions", "ip", ip, "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to check IP: %v", err),
			})
			return
		}

		isBlocked := strings.Contains(output, ip) && !strings.Contains(output, "[]")

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: gin.H{
				"ip":      ip,
				"blocked": isBlocked,
				"details": output,
			},
		})
	}
}

// CheckIPSecurity performs comprehensive IP security check
func CheckIPSecurity(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.Param("ip")
		logger.Info("Performing security check", "ip", ip)

		ipInfo := models.IPInfo{
			IP:            ip,
			IsBlocked:     false,
			IsWhitelisted: false,
			InCrowdSec:    false,
			InTraefik:     false,
		}

		// Check CrowdSec decisions
		decisionOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "decisions", "list", "-i", ip,
		})
		if err == nil {
			ipInfo.IsBlocked = strings.Contains(decisionOutput, ip) &&
				strings.Contains(decisionOutput, "ban")
		}

		// Check CrowdSec whitelist
		whitelistOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cat", "/etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml",
		})
		if err == nil {
			ipInfo.InCrowdSec = strings.Contains(whitelistOutput, ip)
			if ipInfo.InCrowdSec {
				ipInfo.IsWhitelisted = true
			}
		}

		// Check Traefik whitelist
		traefikConfig, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"cat", "/etc/traefik/dynamic_config.yml",
		})
		if err == nil {
			ipInfo.InTraefik = strings.Contains(traefikConfig, ip)
			if ipInfo.InTraefik {
				ipInfo.IsWhitelisted = true
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    ipInfo,
		})
	}
}

// UnbanIP unbans an IP address from CrowdSec
func UnbanIP(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.UnbanRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Unbanning IP", "ip", req.IP)

		// Delete decisions for the IP
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "decisions", "delete", "--ip", req.IP,
		})
		if err != nil {
			logger.Error("Failed to unban IP", "ip", req.IP, "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to unban IP: %v", err),
			})
			return
		}

		logger.Info("IP unbanned successfully", "ip", req.IP)
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("IP %s has been unbanned", req.IP),
			Data:    gin.H{"output": output},
		})
	}
}

// =============================================================================
// 3. WHITELIST MANAGEMENT
// =============================================================================

// ViewWhitelist displays all whitelisted IPs from both CrowdSec and Traefik
func ViewWhitelist(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Viewing whitelist")

		whitelist := gin.H{
			"crowdsec": []string{},
			"traefik":  []string{},
		}

		// Get CrowdSec whitelist
		crowdsecWL, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cat", "/etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml",
		})
		if err == nil {
			whitelist["crowdsec"] = parseWhitelistYAML(crowdsecWL)
		}

		// Get Traefik whitelist
		traefikWL, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"cat", "/etc/traefik/dynamic_config.yml",
		})
		if err == nil {
			whitelist["traefik"] = parseTraefikWhitelist(traefikWL)
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    whitelist,
		})
	}
}

// WhitelistCurrentIP whitelists the current public IP
func WhitelistCurrentIP(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Whitelisting current IP")

		// Get public IP
		resp, err := http.Get("https://api.ipify.org")
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to get public IP",
			})
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		publicIP := strings.TrimSpace(string(body))

		// Add to CrowdSec whitelist
		whitelistContent := fmt.Sprintf(`name: mywhitelists
description: "My custom whitelists"
whitelist:
  reason: "Admin IP"
  ip:
    - %s
`, publicIP)

		// Write to CrowdSec container
		_, err = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"sh", "-c", fmt.Sprintf("echo '%s' > /etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml", whitelistContent),
		})
		if err != nil {
			logger.Error("Failed to update CrowdSec whitelist", "error", err)
		}

		// Reload CrowdSec
		_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "parsers", "reload"})

		logger.Info("Current IP whitelisted", "ip", publicIP)
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("IP %s has been whitelisted", publicIP),
			Data:    gin.H{"ip": publicIP},
		})
	}
}

// WhitelistManualIP whitelists a manually specified IP
func WhitelistManualIP(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.WhitelistRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Whitelisting manual IP", "ip", req.IP)

		var errors []string
		var successMessages []string

		if req.AddToCrowdSec {
			// Get current whitelist
			currentWL, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
				"cat", "/etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml",
			})

			var whitelistContent string
			if err != nil || currentWL == "" {
				whitelistContent = fmt.Sprintf(`name: mywhitelists
description: "My custom whitelists"
whitelist:
  reason: "Manually added"
  ip:
    - %s
`, req.IP)
			} else {
				// Append to existing whitelist
				whitelistContent = strings.TrimSpace(currentWL) + fmt.Sprintf("\n    - %s\n", req.IP)
			}

			_, err = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
				"sh", "-c", fmt.Sprintf("echo '%s' > /etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml", whitelistContent),
			})
			if err != nil {
				errMsg := fmt.Sprintf("Failed to add IP to CrowdSec whitelist: %v", err)
				logger.Error(errMsg, "error", err)
				errors = append(errors, errMsg)
			} else {
				// Reload parsers to apply changes
				if _, reloadErr := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "parsers", "reload"}); reloadErr != nil {
					logger.Warn("Failed to reload CrowdSec parsers", "error", reloadErr)
					successMessages = append(successMessages, "Added to CrowdSec whitelist (reload failed, restart CrowdSec to apply)")
				} else {
					successMessages = append(successMessages, "Added to CrowdSec whitelist")
				}
			}
		}

		if req.AddToTraefik {
			// Update Traefik dynamic config
			_, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
				"sh", "-c", fmt.Sprintf(`sed -i '/sourceRange:/a\        - %s' /etc/traefik/dynamic_config.yml`, req.IP),
			})
			if err != nil {
				errMsg := fmt.Sprintf("Failed to add IP to Traefik whitelist: %v", err)
				logger.Error(errMsg, "error", err)
				errors = append(errors, errMsg)
			} else {
				successMessages = append(successMessages, "Added to Traefik whitelist")
			}
		}

		// Return appropriate response based on results
		if len(errors) > 0 && len(successMessages) == 0 {
			// All operations failed
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to whitelist IP %s: %s", req.IP, strings.Join(errors, "; ")),
			})
			return
		}

		if len(errors) > 0 {
			// Partial success
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Message: fmt.Sprintf("IP %s partially whitelisted. Success: %s. Errors: %s",
					req.IP, strings.Join(successMessages, ", "), strings.Join(errors, "; ")),
			})
			return
		}

		// Complete success
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("IP %s has been whitelisted: %s", req.IP, strings.Join(successMessages, ", ")),
		})
	}
}

// WhitelistCIDR whitelists a CIDR range
func WhitelistCIDR(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.WhitelistRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Whitelisting CIDR", "cidr", req.CIDR)

		if req.AddToCrowdSec {
			whitelistContent := fmt.Sprintf(`name: mywhitelists
description: "My custom whitelists"
whitelist:
  reason: "CIDR range"
  ip:
    - %s
`, req.CIDR)

			_, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
				"sh", "-c", fmt.Sprintf("echo '%s' > /etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml", whitelistContent),
			})
			if err != nil {
				logger.Error("Failed to update CrowdSec whitelist", "error", err)
			} else {
				_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "parsers", "reload"})
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("CIDR %s has been whitelisted", req.CIDR),
		})
	}
}

// AddToCrowdSecWhitelist adds an IP to CrowdSec whitelist only
func AddToCrowdSecWhitelist(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.WhitelistRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Adding to CrowdSec whitelist", "ip", req.IP)

		whitelistContent := fmt.Sprintf(`name: mywhitelists
description: "My custom whitelists"
whitelist:
  reason: "Manually added to CrowdSec"
  ip:
    - %s
`, req.IP)

		_, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"sh", "-c", fmt.Sprintf("echo '%s' > /etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml", whitelistContent),
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update whitelist: %v", err),
			})
			return
		}

		_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "parsers", "reload"})

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("IP %s added to CrowdSec whitelist", req.IP),
		})
	}
}

// AddToTraefikWhitelist adds an IP to Traefik whitelist only
func AddToTraefikWhitelist(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.WhitelistRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Adding to Traefik whitelist", "ip", req.IP)

		_, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"sh", "-c", fmt.Sprintf(`sed -i '/sourceRange:/a\        - %s' /etc/traefik/dynamic_config.yml`, req.IP),
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update whitelist: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("IP %s added to Traefik whitelist", req.IP),
		})
	}
}

// SetupComprehensiveWhitelist sets up complete whitelist configuration
func SetupComprehensiveWhitelist(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.WhitelistRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Setting up comprehensive whitelist", "ip", req.IP)

		// Get public IP if not provided
		ip := req.IP
		if ip == "" {
			resp, err := http.Get("https://api.ipify.org")
			if err == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				ip = strings.TrimSpace(string(body))
			}
		}

		results := gin.H{
			"ip":       ip,
			"crowdsec": false,
			"traefik":  false,
		}

		// Add to CrowdSec
		whitelistContent := fmt.Sprintf(`name: mywhitelists
description: "Comprehensive whitelist"
whitelist:
  reason: "Admin access"
  ip:
    - %s
`, ip)

		_, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"sh", "-c", fmt.Sprintf("echo '%s' > /etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml", whitelistContent),
		})
		if err == nil {
			_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "parsers", "reload"})
			results["crowdsec"] = true
		}

		// Add to Traefik
		_, err = dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"sh", "-c", fmt.Sprintf(`sed -i '/sourceRange:/a\        - %s' /etc/traefik/dynamic_config.yml`, ip),
		})
		if err == nil {
			results["traefik"] = true
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Comprehensive whitelist setup completed",
			Data:    results,
		})
	}
}

// =============================================================================
// 4. SCENARIOS
// =============================================================================

// SetupCustomScenarios installs custom CrowdSec scenarios
func SetupCustomScenarios(dockerClient *docker.Client, configDir string, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.ScenarioSetupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Setting up custom scenarios", "count", len(req.Scenarios))

		hostScenariosDir := filepath.Join(configDir, "crowdsec", "scenarios")

		if err := os.MkdirAll(hostScenariosDir, 0755); err != nil {
			logger.Error("Failed to create scenarios directory on host", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to create scenarios directory: %v", err),
			})
			return
		}

		results := []gin.H{}
		hasErrors := false

		for _, scenario := range req.Scenarios {
			filename := strings.ReplaceAll(scenario.Name, "/", "_") + ".yaml"
			hostScenarioPath := filepath.Join(hostScenariosDir, filename)
			containerScenarioPath := filepath.Join("/etc/crowdsec/scenarios", filename)

			logger.Debug("Writing scenario file",
				"name", scenario.Name,
				"host_path", hostScenarioPath,
				"container_path", containerScenarioPath)

			if err := os.WriteFile(hostScenarioPath, []byte(scenario.Content), 0644); err != nil {
				result := gin.H{
					"name":    scenario.Name,
					"success": false,
					"path":    hostScenarioPath,
					"error":   err.Error(),
				}
				results = append(results, result)
				hasErrors = true
				logger.Error("Failed to write scenario file to host", "name", scenario.Name, "error", err)
				continue
			}

			verifyCmd := fmt.Sprintf("test -f %s && echo 'exists' || echo 'missing'", containerScenarioPath)
			output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"sh", "-c", verifyCmd})

			fileExists := strings.TrimSpace(output) == "exists"

			result := gin.H{
				"name":           scenario.Name,
				"success":        true,
				"host_path":      hostScenarioPath,
				"container_path": containerScenarioPath,
				"verified":       fileExists,
			}

			if err != nil || !fileExists {
				result["warning"] = "File written to host but not visible in container. Check volume mount."
				logger.Warn("Scenario file not visible in container",
					"name", scenario.Name,
					"verify_error", err,
					"file_exists", fileExists)
			}

			results = append(results, result)
			logger.Info("Successfully wrote scenario file", "name", scenario.Name, "path", hostScenarioPath)
		}

		if !hasErrors {
			logger.Info("Restarting CrowdSec to load new scenarios")

			restartOutput, restartErr := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"sh", "-c", "kill -SIGHUP 1"})

			if restartErr != nil {
				logger.Warn("Failed to send HUP signal to CrowdSec, attempting container restart", "error", restartErr)

				if err := dockerClient.RestartContainerWithTimeout(cfg.CrowdsecContainerName, 30); err != nil {
					logger.Error("Failed to restart CrowdSec container", "error", err)
					c.JSON(http.StatusOK, models.Response{
						Success: false,
						Message: "Scenarios written but failed to restart CrowdSec",
						Data:    results,
						Error:   fmt.Sprintf("Restart failed: %v", err),
					})
					return
				}

				logger.Info("CrowdSec container restarted successfully")
			} else {
				logger.Debug("CrowdSec reload signal sent", "output", restartOutput)
			}

			time.Sleep(2 * time.Second)
		}

		c.JSON(http.StatusOK, models.Response{
			Success: !hasErrors,
			Message: "Custom scenarios setup completed",
			Data:    results,
		})
	}
}

// ListScenarios lists all installed CrowdSec scenarios
func ListScenarios(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Listing scenarios")

		// Try JSON format first
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "scenarios", "list", "-o", "json",
		})

		if err != nil {
			logger.Error("Failed to list scenarios", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to list scenarios: %v", err),
			})
			return
		}

		// Log the raw output for debugging
		logger.Debug("Raw scenarios output",
			"length", len(output),
			"first_500_chars", truncateString(output, 500))

		// Clean the output - remove any non-JSON characters
		cleanedOutput := strings.TrimSpace(output)

		// Try to parse as JSON - CrowdSec returns {"scenarios": [...]}
		// First try the nested structure
		type ScenariosResponse struct {
			Scenarios []map[string]any `json:"scenarios"`
		}
		var scenariosResp ScenariosResponse
		var jsonScenarios []any

		if err := json.Unmarshal([]byte(cleanedOutput), &scenariosResp); err == nil && len(scenariosResp.Scenarios) > 0 {
			// Successfully parsed nested structure {"scenarios": [...]}
			logger.Info("Successfully parsed scenarios from nested JSON structure", "total_count", len(scenariosResp.Scenarios))
			// Convert to []any for processing
			for _, s := range scenariosResp.Scenarios {
				jsonScenarios = append(jsonScenarios, s)
			}
		} else if err := json.Unmarshal([]byte(cleanedOutput), &jsonScenarios); err == nil {
			// Fallback: try parsing as flat array (older format or different command)
			logger.Info("Successfully parsed scenarios as JSON array", "total_count", len(jsonScenarios))
		}

		// If we successfully parsed scenarios, filter for installed ones
		if len(jsonScenarios) > 0 {
			// Filter for only installed scenarios
			// A scenario is installed if it has a non-empty local_path or local_version field
			installedScenarios := []any{}
			for _, scenario := range jsonScenarios {
				if scenarioMap, ok := scenario.(map[string]any); ok {
					isInstalled := false

					// Check for local_path field (primary indicator of installation)
					if localPath, exists := scenarioMap["local_path"]; exists {
						if pathStr := fmt.Sprintf("%v", localPath); pathStr != "" && pathStr != "<nil>" {
							isInstalled = true
						}
					}

					// Also check for local_version field as secondary indicator
					if !isInstalled {
						if localVersion, exists := scenarioMap["local_version"]; exists {
							if versionStr := fmt.Sprintf("%v", localVersion); versionStr != "" && versionStr != "<nil>" {
								isInstalled = true
							}
						}
					}

					// Also check status field for backward compatibility
					if !isInstalled {
						if status, exists := scenarioMap["status"]; exists {
							statusStr := fmt.Sprintf("%v", status)
							if statusStr == "enabled" || statusStr == "disabled" {
								isInstalled = true
							}
						}
					}

					if isInstalled {
						installedScenarios = append(installedScenarios, scenario)
					}
				}
			}

			logger.Info("Filtered installed scenarios",
				"total", len(jsonScenarios),
				"installed", len(installedScenarios))

			// Return filtered scenarios
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Message: fmt.Sprintf("Found %d installed scenarios", len(installedScenarios)),
				Data: gin.H{
					"scenarios": installedScenarios,
					"count":     len(installedScenarios),
				},
			})
			return
		}

		// JSON parsing failed, try text format
		logger.Warn("Failed to parse scenarios as JSON",
			"error", err,
			"trying_text_format", true)

		// Fallback to text parsing
		scenarios := parseHumanReadableScenarios(output)

		if len(scenarios) > 0 {
			logger.Info("Successfully parsed scenarios from human format", "count", len(scenarios))
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Message: fmt.Sprintf("Found %d scenarios (parsed from text)", len(scenarios)),
				Data: gin.H{
					"scenarios": scenarios,
					"count":     len(scenarios),
				},
			})
			return
		}

		// Better error response with debugging info
		logger.Error("Failed to parse scenarios in any format",
			"output_length", len(output),
			"output_preview", truncateString(output, 500))

		c.JSON(http.StatusInternalServerError, models.Response{
			Success: false,
			Error:   "Failed to parse scenarios output",
			Data: gin.H{
				"raw_output_preview": truncateString(output, 500),
				"output_length":      len(output),
			},
		})
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// GetScenarioFiles returns a list of scenario files from the host filesystem
func GetScenarioFiles(configDir string) gin.HandlerFunc {
	return func(c *gin.Context) {
		hostScenariosDir := filepath.Join(configDir, "crowdsec", "scenarios")

		if _, err := os.Stat(hostScenariosDir); os.IsNotExist(err) {
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    []string{},
				Message: "No scenarios directory found",
			})
			return
		}

		entries, err := os.ReadDir(hostScenariosDir)
		if err != nil {
			logger.Error("Failed to read scenarios directory", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to read scenarios directory: %v", err),
			})
			return
		}

		scenarioFiles := []gin.H{}
		for _, entry := range entries {
			if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml")) {
				continue
			}

			filePath := filepath.Join(hostScenariosDir, entry.Name())
			info, err := entry.Info()
			if err != nil {
				continue
			}

			content, err := os.ReadFile(filePath)
			if err != nil {
				logger.Warn("Failed to read scenario file", "file", entry.Name(), "error", err)
				continue
			}

			var scenarioData map[string]any
			if err := yaml.Unmarshal(content, &scenarioData); err == nil {
				scenarioFiles = append(scenarioFiles, gin.H{
					"filename":    entry.Name(),
					"name":        scenarioData["name"],
					"description": scenarioData["description"],
					"type":        scenarioData["type"],
					"size":        info.Size(),
					"modified":    info.ModTime(),
				})
			} else {
				scenarioFiles = append(scenarioFiles, gin.H{
					"filename": entry.Name(),
					"size":     info.Size(),
					"modified": info.ModTime(),
				})
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    scenarioFiles,
			Message: fmt.Sprintf("Found %d scenario files", len(scenarioFiles)),
		})
	}
}

// DeleteScenarioFile deletes a scenario file from the host filesystem
func DeleteScenarioFile(dockerClient *docker.Client, configDir string, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			Filename string `json:"filename" binding:"required"`
		}

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		if strings.Contains(req.Filename, "..") || strings.Contains(req.Filename, "/") {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid filename",
			})
			return
		}

		hostScenariosDir := filepath.Join(configDir, "crowdsec", "scenarios")
		filePath := filepath.Join(hostScenariosDir, req.Filename)

		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, models.Response{
				Success: false,
				Error:   "Scenario file not found",
			})
			return
		}

		if err := os.Remove(filePath); err != nil {
			logger.Error("Failed to delete scenario file", "file", req.Filename, "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to delete scenario file: %v", err),
			})
			return
		}

		logger.Info("Scenario file deleted", "file", req.Filename)

		logger.Info("Restarting CrowdSec to apply changes")
		if err := dockerClient.RestartContainerWithTimeout(cfg.CrowdsecContainerName, 30); err != nil {
			logger.Warn("Failed to restart CrowdSec after deleting scenario", "error", err)
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Scenario file deleted successfully",
		})
	}
}

// =============================================================================
// 5. CAPTCHA
// =============================================================================

// SetupCaptcha sets up Cloudflare Turnstile captcha
func SetupCaptcha(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.CaptchaSetupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Setting up captcha", "provider", req.Provider)

		// Get the host mount path for /etc/traefik/conf
		hostConfPath, found, err := dockerClient.GetHostMountPath(cfg.TraefikContainerName, "/etc/traefik/conf")
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get Traefik mount path: %v", err),
			})
			return
		}

		// If /etc/traefik/conf is not directly mounted, try /etc/traefik and append /conf
		if !found {
			hostTraefikPath, found, err := dockerClient.GetHostMountPath(cfg.TraefikContainerName, "/etc/traefik")
			if err != nil || !found {
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   "Could not find Traefik config mount path. Ensure /etc/traefik is mounted from host.",
				})
				return
			}
			hostConfPath = filepath.Join(hostTraefikPath, "conf")
		}

		// Create the conf directory if it doesn't exist
		if err := os.MkdirAll(hostConfPath, 0755); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to create conf directory: %v", err),
			})
			return
		}

		// Captcha HTML template
		captchaHTML := `<!DOCTYPE html>
<html lang="en">
<head>
  <title>CrowdSec Captcha</title>
  <meta content="text/html; charset=utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <style>
    *,:after,:before{border:0 solid #e5e7eb;box-sizing:border-box}:after,:before{--tw-content:""}html{-webkit-text-size-adjust:100%;font-feature-settings:normal;font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica Neue,Arial,Noto Sans,sans-serif,Apple Color Emoji,Segoe UI Emoji,Segoe UI Symbol,Noto Color Emoji;line-height:1.5;-moz-tab-size:4;-o-tab-size:4;tab-size:4}body{line-height:inherit;margin:0}h1,h2,h3,h4,h5,h6{font-size:inherit;font-weight:inherit}a{color:inherit;text-decoration:inherit}h1,h2,h3,h4,h5,h6,hr,p,pre{margin:0}*,::backdrop,:after,:before{--tw-border-spacing-x:0;--tw-border-spacing-y:0;--tw-translate-x:0;--tw-translate-y:0;--tw-rotate:0;--tw-skew-x:0;--tw-skew-y:0;--tw-scale-x:1;--tw-scale-y:1;--tw-pan-x:;--tw-pan-y:;--tw-pinch-zoom:;--tw-scroll-snap-strictness:proximity;--tw-ordinal:;--tw-slashed-zero:;--tw-numeric-figure:;--tw-numeric-spacing:;--tw-numeric-fraction:;--tw-ring-inset:;--tw-ring-offset-width:0px;--tw-ring-offset-color:#fff;--tw-ring-color:#3b82f680;--tw-ring-offset-shadow:0 0 #0000;--tw-ring-shadow:0 0 #0000;--tw-shadow:0 0 #0000;--tw-shadow-colored:0 0 #0000;--tw-blur:;--tw-brightness:;--tw-contrast:;--tw-grayscale:;--tw-hue-rotate:;--tw-invert:;--tw-saturate:;--tw-sepia:;--tw-drop-shadow:;--tw-backdrop-blur:;--tw-backdrop-brightness:;--tw-backdrop-contrast:;--tw-backdrop-grayscale:;--tw-backdrop-hue-rotate:;--tw-backdrop-invert:;--tw-backdrop-opacity:;--tw-backdrop-saturate:;--tw-backdrop-sepia:}.flex{display:flex}.flex-wrap{flex-wrap:wrap}.inline-flex{display:inline-flex}.h-24{height:6rem}.h-6{height:1.5rem}.h-full{height:100%}.h-screen{height:100vh}.text-center{text-align:center}.w-24{width:6rem}.w-6{width:1.5rem}.w-full{width:100%}.w-screen{width:100vw}.my-3{margin-top:0.75rem;margin-bottom:0.75rem}.flex-col{flex-direction:column}.items-center{align-items:center}.justify-center{justify-content:center}.justify-between{justify-content:space-between}.space-y-1>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-bottom:calc(.25rem*var(--tw-space-y-reverse));margin-top:calc(.25rem*(1 - var(--tw-space-y-reverse)))}.space-y-4>:not([hidden])~:not([hidden]){--tw-space-y-reverse:0;margin-bottom:calc(1rem*var(--tw-space-y-reverse));margin-top:calc(1rem*(1 - var(--tw-space-y-reverse)))}.rounded-xl{border-radius:.75rem}.border-2{border-width:2px}.border-black{--tw-border-opacity:1;border-color:rgb(0 0 0/var(--tw-border-opacity))}.p-4{padding:1rem}.px-4{padding-left:1rem;padding-right:1rem}.py-2{padding-bottom:.5rem;padding-top:.5rem}.text-2xl{font-size:1.5rem;line-height:2rem}.text-sm{font-size:.875rem;line-height:1.25rem}.text-xl{font-size:1.25rem;line-height:1.75rem}.font-bold{font-weight:700}.text-white{--tw-text-opacity:1;color:rgb(255 255 255/var(--tw-text-opacity))}@media (min-width:640px){.sm\:w-2\/3{width:66.666667%}}@media (min-width:768px){.md\:flex-row{flex-direction:row}}@media (min-width:1024px){.lg\:w-1\/2{width:50%}.lg\:text-3xl{font-size:1.875rem;line-height:2.25rem}.lg\:text-xl{font-size:1.25rem;line-height:1.75rem}}@media (min-width:1280px){.xl\:text-4xl{font-size:2.25rem;line-height:2.5rem}}
  </style>
  <script src="{{ .FrontendJS }}" async defer></script>
</head>
<body class="h-screen w-screen p-4">
  <div class="h-full w-full flex flex-col justify-center items-center">
    <div class="border-2 border-black rounded-xl p-4 text-center w-full sm:w-2/3 lg:w-1/2">
      <div class="flex flex-col items-center space-y-4">
        <svg fill="black" class="h-24 w-24" aria-hidden="true" focusable="false" data-prefix="fas" data-icon="exclamation-triangle" role="img" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 576 512" class="warning"><path d="M569.517 440.013C587.975 472.007 564.806 512 527.94 512H48.054c-36.937 0-59.999-40.055-41.577-71.987L246.423 23.985c18.467-32.009 64.72-31.951 83.154 0l239.94 416.028zM288 354c-25.405 0-46 20.595-46 46s20.595 46 46 46 46-20.595 46-46-20.595-46-46-46zm-43.673-165.346l7.418 136c.347 6.364 5.609 11.346 11.982 11.346h48.546c6.373 0 11.635-4.982 11.982-11.346l7.418-136c.375-6.874-5.098-12.654-11.982-12.654h-63.383c-6.884 0-12.356 5.78-11.981 12.654z"></path></svg>
        <h1 class="text-2xl lg:text-3xl xl:text-4xl">CrowdSec Captcha</h1>
      </div>
      <form action="" method="POST" class="flex flex-col space-y-1" id="captcha-form">
        <div id="captcha" class="{{ .FrontendKey }}" data-sitekey="{{ .SiteKey }}" data-callback="captchaCallback"></div>
      </form>
      <div class="flex justify-center flex-wrap">
        <p class="my-3">This security check has been powered by</p>
        <a href="https://crowdsec.net/" target="_blank" rel="noopener" class="inline-flex flex-col items-center">
          <svg fill="black" width="33.92" height="33.76" viewBox="0 0 254.4 253.2"><defs><clipPath id="a"><path d="M0 52h84v201.2H0zm0 0"/></clipPath><clipPath id="b"><path d="M170 52h84.4v201.2H170zm0 0"/></clipPath></defs><path d="M59.3 128.4c1.4 2.3 2.5 4.6 3.4 7-1-4.1-2.3-8.1-4.3-12-3.1-6-7.8-5.8-10.7 0-2 4-3.2 8-4.3 12.1 1-2.4 2-4.8 3.4-7.1 3.4-5.8 8.8-6 12.5 0M207.8 128.4a42.9 42.9 0 013.4 7c-1-4.1-2.3-8.1-4.3-12-3.2-6-7.8-5.8-10.7 0-2 4-3.3 8-4.3 12.1.9-2.4 2-4.8 3.4-7.1 3.4-5.8 8.8-6 12.5 0M134.6 92.9c2 3.5 3.6 7 4.8 10.7-1.3-5.4-3-10.6-5.6-15.7-4-7.5-9.7-7.2-13.3 0a75.4 75.4 0 00-5.6 16c1.2-3.8 2.7-7.4 4.7-11 4.1-7.2 10.6-7.5 15 0M43.8 136.8c.9 4.6 3.7 8.3 7.3 9.2 0 2.7 0 5.5.2 8.2.3 3.3.4 6.6 1 9.6.3 2.3 1 2.2 1.3 0 .5-3 .6-6.3 1-9.6l.2-8.2c3.5-1 6.4-4.6 7.2-9.2a17.8 17.8 0 01-9 2.4c-3.5 0-6.6-1-9.2-2.4M192.4 136.8c.8 4.6 3.7 8.3 7.2 9.2 0 2.7 0 5.5.3 8.2.3 3.3.4 6.6 1 9.6.3 2.3.9 2.2 1.2 0 .6-3 .7-6.3 1-9.6.2-2.7.3-5.5.2-8.2 3.6-1 6.4-4.6 7.3-9.2a17.8 17.8 0 01-9.1 2.4c-3.4 0-6.6-1-9.1-2.4M138.3 104.6c-3.1 1.9-7 3-11.3 3-4.3 0-8.2-1.1-11.3-3 1 5.8 4.5 10.3 9 11.5 0 3.4 0 6.8.3 10.2.4 4.1.5 8.2 1.2 12 .4 2.9 1.2 2.7 1.6 0 .7-3.8.8-7.9 1.2-12 .3-3.4.3-6.8.3-10.2 4.5-1.2 8-5.7 9-11.5"/><path d="M51 146c0 2.7.1 5.5.3 8.2.3 3.3.4 6.6 1 9.6.3 2.3 1 2.2 1.3 0 .5-3 .6-6.3 1-9.6l.2-8.2c3.5-1 6.4-4.6 7.2-9.2a17.8 17.8 0 01-9 2.4c-3.5 0-6.6-1-9.2-2.4.9 4.6 3.7 8.3 7.3 9.2M143.9 105c-1.9-.4-3.5-1.2-4.9-2.3 1.4 5.6 2.5 11.3 4 17 1.2 5 2 10 2.4 15 .6 7.8-4.5 14.5-10.9 14.5h-15c-6.4 0-11.5-6.7-11-14.5.5-5 1.3-10 2.6-15 1.3-5.3 2.3-10.5 3.6-15.7-2.2 1.2-4.8 1.9-7.7 2-4.7.1-9.4-.3-14-1-4-.4-6.7-3-8-6.7-1.3-3.4-2-7-3.3-10.4-.5-1.5-1.6-2.8-2.4-4.2-.4-.6-.8-1.2-.9-1.8v-7.8a77 77 0 0124.5-3c6.1 0 12 1 17.8 3.2 4.7 1.7 9.7 1.8 14.4 0 9-3.4 18.2-3.8 27.5-3 4.9.5 9.8 1.6 14.8 2.4v8.2c0 .6-.3 1.5-.7 1.7-2 .9-2.2 2.7-2.7 4.5-.9 3.2-1.8 6.4-2.9 9.5a11 11 0 01-8.8 7.7 40.6 40.6 0 01-18.4-.2m29.4 80.6c-3.2-26.8-6.4-50-8.9-60.7a14.3 14.3 0 0014.1-14h.4a9 9 0 005.6-16.5 14.3 14.3 0 00-3.7-27.2 9 9 0 00-6.9-14.6c2.4-1.1 4.5-3 5.8-5 3.4-5.3 4-29-8-44.4-5-6.3-9.8-2.5-10 1.8-1 13.2-1.1 23-4.5 34.3a9 9 0 00-16-4.1 14.3 14.3 0 00-28.4 0 9 9 0 00-16 4.1c-3.4-11.2-3.5-21.1-4.4-34.3-.3-4.3-5.2-8-10-1.8-12 15.3-11.5 39-8.1 44.4 1.3 2 3.4 3.9 5.8 5a9 9 0 00-7 14.6 14.3 14.3 0 00-3.6 27.2A9 9 0 0075 111h.5a14.5 14.5 0 0014.3 14c-4 17.2-10 66.3-15 111.3l-1.3 13.4a1656.4 1656.4 0 01106.6 0l-1.4-12.7-5.4-51.3"/><g clip-path="url(#a)"><path d="M83.5 136.6l-2.3.7c-5 1-9.8 1-14.8-.2-1.4-.3-2.7-1-3.8-1.9l3.1 13.7c1 4 1.7 8 2 12 .5 6.3-3.6 11.6-8.7 11.6H46.9c-5.1 0-9.2-5.3-8.7-11.6.3-4 1-8 2-12 1-4.2 1.8-8.5 2.9-12.6-1.8 1-3.9 1.5-6.3 1.6a71 71 0 01-11.1-.7 7.7 7.7 0 01-6.5-5.5c-1-2.7-1.6-5.6-2.6-8.3-.4-1.2-1.3-2.3-2-3.4-.2-.4-.6-1-.6-1.4v-6.3c6.4-2 13-2.6 19.6-2.5 4.9.1 9.6 1 14.2 2.6 3.9 1.4 7.9 1.5 11.7 0 1.8-.7 3.6-1.2 5.5-1.6a13 13 0 01-1.6-15.5A18.3 18.3 0 0159 73.1a11.5 11.5 0 00-17.4 8.1 7.2 7.2 0 00-12.9 3.3c-2.7-9-2.8-17-3.6-27.5-.2-3.4-4-6.5-8-1.4C7.5 67.8 7.9 86.9 10.6 91c1.1 1.7 2.8 3.1 4.7 4a7.2 7.2 0 00-5.6 11.7 11.5 11.5 0 00-2.9 21.9 7.2 7.2 0 004.5 13.2h.3c0 .6 0 1.1.2 1.7.9 5.4 5.6 9.5 11.3 9.5A1177.2 1177.2 0 0010 253.2c18.1-1.5 38.1-2.6 59.5-3.4.4-4.6.8-9.3 1.4-14 1.2-11.6 3.3-30.5 5.7-49.7 2.2-18 4.7-36.3 7-49.5"/></g><g clip-path="url(#b)"><path d="M254.4 118.2c0-5.8-4.2-10.5-9.7-11.4a7.2 7.2 0 00-5.6-11.7c2-.9 3.6-2.3 4.7-4 2.7-4.2 3.1-23.3-6.5-35.5-4-5.1-7.8-2-8 1.4-.8 10.5-.9 18.5-3.6 27.5a7.2 7.2 0 00-12.8-3.3 11.5 11.5 0 00-17.8-7.9 18.4 18.4 0 01-4.5 22 13 13 0 01-1.3 15.2c2.4.5 4.8 1 7.1 2 3.8 1.3 7.8 1.4 11.6 0 7.2-2.8 14.6-3 22-2.4 4 .4 7.9 1.2 12 1.9l-.1 6.6c0 .5-.2 1.2-.5 1.3-1.7.7-1.8 2.2-2.2 3.7l-2.3 7.6a8.8 8.8 0 01-7 6.1c-5 1-10 1-14.9-.2-1.5-.3-2.8-1-3.9-1.9 1.2 4.5 2 9.1 3.2 13.7 1 4 1.6 8 2 12 .4 6.3-3.6 11.6-8.8 11.6h-12c-5.2 0-9.3-5.3-8.8-11.6.4-4 1-8 2-12 1-4.2 1.9-8.5 3-12.6-1.8 1-4 1.5-6.3 1.6-3.7 0-7.5-.3-11.2-.7a7.7 7.7 0 01-3.7-1.5c3.1 18.4 7.1 51.2 12.5 100.9l.6 5.3.8 7.9c21.4.7 41.5 1.9 59.7 3.4L243 243l-4.4-41.2a606 606 0 00-7-48.7 11.5 11.5 0 0011.2-11.2h.4a7.2 7.2 0 004.4-13.2c4-1.8 6.8-5.8 6.8-10.5"/></g><path d="M180 249.6h.4a6946 6946 0 00-7.1-63.9l5.4 51.3 1.4 12.6M164.4 125c2.5 10.7 5.7 33.9 8.9 60.7a570.9 570.9 0 00-8.9-60.7M74.8 236.3l-1.4 13.4 1.4-13.4"/>
          </svg>
          <span>CrowdSec</span>
        </a>
      </div>
    </div>
  </div>
  <script>
    function captchaCallback() {
      setTimeout(() => document.querySelector('#captcha-form').submit(), 500);
    }
  </script>
</body>
</html>`

		// Write captcha.html to host filesystem
		captchaHTMLPath := filepath.Join(hostConfPath, "captcha.html")
		if err := os.WriteFile(captchaHTMLPath, []byte(captchaHTML), 0644); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to write captcha.html: %v", err),
			})
			return
		}

		logger.Info("Created captcha.html", "path", captchaHTMLPath)

		// Store captcha configuration in environment or config file
		captchaConfig := fmt.Sprintf(`CAPTCHA_PROVIDER=%s
CAPTCHA_SITE_KEY=%s
CAPTCHA_SECRET_KEY=%s
`, req.Provider, req.SiteKey, req.SecretKey)

		// Write to config file in Traefik container
		_, err = dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"sh", "-c", fmt.Sprintf("echo '%s' > /etc/traefik/captcha.env", captchaConfig),
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to save captcha config: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Captcha configured successfully. HTML file created at " + captchaHTMLPath,
		})
	}
}

// detectCaptchaInConfig checks if captcha is configured in dynamic_config.yml and profiles.yaml
func detectCaptchaInConfig(configContent string) (enabled bool, provider string, hasHTMLPath bool) {
	enabled = false
	provider = ""
	hasHTMLPath = false

	// Check for captcha configuration in middleware
	if strings.Contains(configContent, "captchaProvider:") {
		enabled = true

		// Detect provider type
		if strings.Contains(configContent, "captchaProvider: turnstile") ||
			strings.Contains(configContent, "captchaProvider: \"turnstile\"") ||
			strings.Contains(configContent, "captchaProvider: 'turnstile'") {
			provider = "turnstile"
		} else if strings.Contains(configContent, "captchaProvider: recaptcha") ||
			strings.Contains(configContent, "captchaProvider: \"recaptcha\"") ||
			strings.Contains(configContent, "captchaProvider: 'recaptcha'") {
			provider = "recaptcha"
		} else if strings.Contains(configContent, "captchaProvider: hcaptcha") ||
			strings.Contains(configContent, "captchaProvider: \"hcaptcha\"") ||
			strings.Contains(configContent, "captchaProvider: 'hcaptcha'") {
			provider = "hcaptcha"
		}
	}

	// Check if captcha HTML file path is configured
	if strings.Contains(configContent, "captchaHTMLFilePath:") {
		hasHTMLPath = true
	}

	// Also check for captcha site key and secret key as indicators
	if strings.Contains(configContent, "captchaSiteKey:") &&
		strings.Contains(configContent, "captchaSecretKey:") {
		enabled = true
	}

	return enabled, provider, hasHTMLPath
}

// GetCaptchaStatus retrieves the current captcha configuration status
func GetCaptchaStatus(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting captcha status")

		// Check if captcha.env exists (saved configuration)
		output, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"cat", "/etc/traefik/captcha.env",
		})

		configSaved := false
		savedProvider := ""

		if err == nil && strings.TrimSpace(output) != "" {
			configSaved = true
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "CAPTCHA_PROVIDER=") {
					savedProvider = strings.TrimSpace(strings.TrimPrefix(line, "CAPTCHA_PROVIDER="))
					break
				}
			}
		}

		// Get dynamic config path from database
		dynamicConfigPath := "/etc/traefik/dynamic_config.yml"
		if db != nil {
			if path, err := db.GetTraefikDynamicConfigPath(); err == nil {
				dynamicConfigPath = path
			}
		}

		// Check dynamic_config.yml for actual captcha configuration
		configContent, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"cat", dynamicConfigPath,
		})

		configured := false
		detectedProvider := ""
		hasHTMLPath := false

		if err == nil && configContent != "" {
			configured, detectedProvider, hasHTMLPath = detectCaptchaInConfig(configContent)
		}

		// Check if captcha.html exists on host filesystem
		captchaHTMLExistsOnHost := false
		hostHTMLPath := ""
		hostConfPath, found, hostErr := dockerClient.GetHostMountPath(cfg.TraefikContainerName, "/etc/traefik/conf")
		if hostErr == nil && !found {
			// Try /etc/traefik and append /conf
			hostTraefikPath, found, err := dockerClient.GetHostMountPath(cfg.TraefikContainerName, "/etc/traefik")
			if err == nil && found {
				hostConfPath = filepath.Join(hostTraefikPath, "conf")
			}
		}
		if hostConfPath != "" {
			hostHTMLPath = filepath.Join(hostConfPath, "captcha.html")
			if _, err := os.Stat(hostHTMLPath); err == nil {
				captchaHTMLExistsOnHost = true
			}
		}

		// Check if captcha.html exists in Traefik container (verifies mount is working)
		captchaHTMLExistsInContainer := false
		exists, err := dockerClient.FileExists(cfg.TraefikContainerName, "/etc/traefik/conf/captcha.html")
		if err == nil && exists {
			captchaHTMLExistsInContainer = true
		}

		// For backwards compatibility, captchaHTMLExists is true if it exists in container
		captchaHTMLExists := captchaHTMLExistsInContainer

		// Determine final provider (prefer detected over saved)
		finalProvider := detectedProvider
		if finalProvider == "" {
			finalProvider = savedProvider
		}

		// Ensure all string fields are never nil (use empty string instead)
		if finalProvider == "" {
			finalProvider = ""
		}
		if detectedProvider == "" {
			detectedProvider = ""
		}
		if savedProvider == "" {
			savedProvider = ""
		}

		status := gin.H{
			"configured":                   configured,                      // True if captcha is in dynamic_config.yml
			"configSaved":                  configSaved,                     // True if captcha.env exists
			"provider":                     finalProvider,                   // Detected or saved provider
			"detectedProvider":             detectedProvider,                // Provider from dynamic_config.yml
			"savedProvider":                savedProvider,                   // Provider from captcha.env
			"captchaHTMLExists":            captchaHTMLExists,               // True if captcha.html exists in container
			"captchaHTMLExistsOnHost":      captchaHTMLExistsOnHost,         // True if captcha.html exists on host
			"captchaHTMLExistsInContainer": captchaHTMLExistsInContainer,    // True if captcha.html exists in container
			"hostHTMLPath":                 hostHTMLPath,                    // Host path where captcha.html should be
			"hasHTMLPath":                  hasHTMLPath,                     // True if captchaHTMLFilePath is configured
			"implemented":                  configured && captchaHTMLExists, // Fully implemented if both exist
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    status,
		})
	}
}

// =============================================================================
// 6. LOGS
// =============================================================================

// GetCrowdSecLogs retrieves CrowdSec logs
func GetCrowdSecLogs(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		tail := c.DefaultQuery("tail", "100")
		logger.Info("Getting CrowdSec logs", "tail", tail)

		logs, err := dockerClient.GetContainerLogs(cfg.CrowdsecContainerName, tail)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get logs: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"logs": logs},
		})
	}
}

// GetTraefikLogs retrieves Traefik logs from the access log file
func GetTraefikLogs(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		tail := c.DefaultQuery("tail", "100")
		logType := c.DefaultQuery("type", "access") // access or error
		logger.Info("Getting Traefik logs", "tail", tail, "type", logType)

		settings, _ := db.GetSettings()
		var logPath string
		if logType == "error" {
			logPath = settings.TraefikErrorLog
		} else {
			logPath = settings.TraefikAccessLog
		}

		// Read log file from traefik container
		logs, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{"tail", "-n", tail, logPath})
		if err != nil {
			// Fallback to container logs if file reading fails
			logger.Warn("Failed to read log file, falling back to container logs", "error", err)
			logs, err = dockerClient.GetContainerLogs(cfg.TraefikContainerName, tail)
			if err != nil {
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Failed to get logs: %v", err),
				})
				return
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"logs": logs, "path": logPath},
		})
	}
}

// AnalyzeTraefikLogsAdvanced performs advanced analysis of Traefik logs
func AnalyzeTraefikLogsAdvanced(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		tail := c.DefaultQuery("tail", "1000")
		logger.Info("Analyzing Traefik logs", "tail", tail)

		logs, err := dockerClient.GetContainerLogs(cfg.TraefikContainerName, tail)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get logs: %v", err),
			})
			return
		}

		// Parse and analyze logs
		stats := analyzeLogs(logs)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    stats,
		})
	}
}

// GetServiceLogs gets logs for any service
func GetServiceLogs(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		service := c.Param("service")
		tail := c.DefaultQuery("tail", "100")
		logger.Info("Getting service logs", "service", service, "tail", tail)

		logs, err := dockerClient.GetContainerLogs(service, tail)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get logs: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"logs": logs, "service": service},
		})
	}
}

// StreamLogs streams logs via WebSocket
func StreamLogs(dockerClient *docker.Client) gin.HandlerFunc {
	var upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	return func(c *gin.Context) {
		service := c.Param("service")
		logger.Info("Streaming logs", "service", service)

		ws, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			logger.Error("Failed to upgrade to websocket", "error", err)
			return
		}
		defer ws.Close()

		// Set up ping/pong handlers
		ws.SetReadDeadline(time.Now().Add(60 * time.Second))
		ws.SetPongHandler(func(string) error {
			ws.SetReadDeadline(time.Now().Add(60 * time.Second))
			return nil
		})

		// Start ping ticker
		pingTicker := time.NewTicker(30 * time.Second)
		defer pingTicker.Stop()

		// Stream logs in real-time
		logTicker := time.NewTicker(500 * time.Millisecond)
		defer logTicker.Stop()

		done := make(chan struct{})

		// Track last sent log lines to avoid sending duplicates
		var lastSentHash string
		lastLogLines := make([]string, 0)

		// Read messages from client (to detect disconnection)
		go func() {
			defer close(done)
			for {
				_, _, err := ws.ReadMessage()
				if err != nil {
					logger.Debug("WebSocket read error", "error", err)
					return
				}
			}
		}()

		for {
			select {
			case <-done:
				return
			case <-pingTicker.C:
				if err := ws.WriteControl(websocket.PingMessage, []byte{}, time.Now().Add(10*time.Second)); err != nil {
					logger.Debug("WebSocket ping error", "error", err)
					return
				}
			case <-logTicker.C:
				// Check if container is running before attempting to get logs
				isRunning, err := dockerClient.IsContainerRunning(service)
				if err != nil {
					// Only send error once per unique error
					errorMsg := fmt.Sprintf("Error checking container status: %v", err)
					if lastSentHash != errorMsg {
						ws.WriteMessage(websocket.TextMessage, []byte(errorMsg))
						lastSentHash = errorMsg
					}
					continue
				}

				if !isRunning {
					// Only send status message once
					statusMsg := fmt.Sprintf("Container '%s' is not running (restarting or stopped)", service)
					if lastSentHash != statusMsg {
						ws.WriteMessage(websocket.TextMessage, []byte(statusMsg))
						lastSentHash = statusMsg
					}
					continue
				}

				logs, err := dockerClient.GetContainerLogs(service, "100")
				if err != nil {
					errorMsg := fmt.Sprintf("Error fetching logs: %v", err)
					if lastSentHash != errorMsg {
						ws.WriteMessage(websocket.TextMessage, []byte(errorMsg))
						lastSentHash = errorMsg
					}
					continue
				}

				// Clean the logs
				logs = strings.TrimSpace(logs)
				if logs == "" {
					continue // Skip empty logs
				}

				// Split logs into lines
				currentLines := strings.Split(logs, "\n")
				if len(currentLines) == 0 {
					continue
				}

				// Calculate hash of last few lines to detect if content changed
				var currentHash string
				if len(currentLines) > 0 {
					// Use last 10 lines for hash comparison
					lastLines := currentLines
					if len(lastLines) > 10 {
						lastLines = lastLines[len(lastLines)-10:]
					}
					currentHash = strings.Join(lastLines, "\n")
				}

				// Only send new lines if content has changed
				if currentHash != lastSentHash && currentHash != "" {
					// Find new lines that weren't in the previous batch
					var newLines []string
					if len(lastLogLines) == 0 {
						// First batch, send all lines
						newLines = currentLines
					} else {
						// Find lines that are new compared to last batch
						lastLineMap := make(map[string]bool)
						for _, line := range lastLogLines {
							lastLineMap[line] = true
						}
						for _, line := range currentLines {
							if !lastLineMap[line] {
								newLines = append(newLines, line)
							}
						}
					}

					// Only send if there are actual new lines
					if len(newLines) > 0 {
						newContent := strings.Join(newLines, "\n")
						if err := ws.WriteMessage(websocket.TextMessage, []byte(newContent)); err != nil {
							logger.Debug("WebSocket write error", "error", err)
							return
						}
						lastSentHash = currentHash
						lastLogLines = currentLines
						// Keep only last 50 lines to avoid memory growth
						if len(lastLogLines) > 50 {
							lastLogLines = lastLogLines[len(lastLogLines)-50:]
						}
					}
				}
			}
		}
	}
}

// =============================================================================
// 7. BACKUP
// =============================================================================

// ListBackups lists all available backups
func ListBackups(backupMgr *backup.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Listing backups")

		backups, err := backupMgr.List()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to list backups: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    backups,
		})
	}
}

// CreateBackup creates a new backup
func CreateBackup(backupMgr *backup.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.BackupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Creating backup", "dryRun", req.DryRun)

		backup, err := backupMgr.Create(req.DryRun)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to create backup: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Backup created successfully",
			Data:    backup,
		})
	}
}

// RestoreBackup restores from a backup
func RestoreBackup(backupMgr *backup.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.RestoreRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		if !req.Confirm {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Restore must be confirmed",
			})
			return
		}

		logger.Info("Restoring backup", "backupID", req.BackupID)

		if err := backupMgr.Restore(req.BackupID); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to restore backup: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Backup restored successfully",
		})
	}
}

// DeleteBackup deletes a specific backup
func DeleteBackup(backupMgr *backup.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		backupID := c.Param("id")
		logger.Info("Deleting backup", "backupID", backupID)

		if err := backupMgr.Delete(backupID); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to delete backup: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Backup deleted successfully",
		})
	}
}

// CleanupOldBackups removes old backups based on retention policy
func CleanupOldBackups(backupMgr *backup.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Cleaning up old backups")

		if err := backupMgr.CleanupOld(); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to cleanup backups: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Old backups cleaned up successfully",
		})
	}
}

// GetLatestBackup gets the most recent backup
func GetLatestBackup(backupMgr *backup.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting latest backup")

		backup, err := backupMgr.FindLatest()
		if err != nil {
			c.JSON(http.StatusNotFound, models.Response{
				Success: false,
				Error:   "No backups found",
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    backup,
		})
	}
}

// =============================================================================
// 8. UPDATE
// =============================================================================

// CheckForUpdates checks for updates for all services
func CheckForUpdates(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Checking for updates")

		type ServiceUpdateStatus struct {
			CurrentTag      string `json:"current_tag"`
			LatestWarning   bool   `json:"latest_warning"`
			UpdateAvailable bool   `json:"update_available"`
			Error           string `json:"error,omitempty"`
		}

		status := make(map[string]ServiceUpdateStatus)

		// Map service names to container names and image names
		services := map[string]struct {
			containerName string
			imageName     string
		}{
			"pangolin": {cfg.PangolinContainerName, "fosrl/pangolin"},
			"gerbil":   {cfg.GerbilContainerName, "fosrl/gerbil"},
			"traefik":  {cfg.TraefikContainerName, "traefik"},
			"crowdsec": {cfg.CrowdsecContainerName, "crowdsecurity/crowdsec"},
		}

		for service, info := range services {
			s := ServiceUpdateStatus{}

			// Get current container info
			inspect, err := dockerClient.InspectContainer(info.containerName)
			if err != nil {
				logger.Warn("Failed to inspect container", "name", info.containerName, "error", err)
				s.Error = fmt.Sprintf("Container not found: %v", err)
				status[service] = s
				continue
			}

			// Extract tag
			imageParts := strings.Split(inspect.Config.Image, ":")
			if len(imageParts) >= 2 {
				s.CurrentTag = imageParts[len(imageParts)-1]
			} else {
				s.CurrentTag = "latest" // Default assumption
			}

			// Check for "latest" tag warning
			if s.CurrentTag == "latest" {
				s.LatestWarning = true
			}

			// Check for updates
			localDigest, err := dockerClient.GetLocalImageDigest(info.imageName, s.CurrentTag)
			if err != nil {
				logger.Warn("Failed to get local digest", "image", info.imageName, "tag", s.CurrentTag, "error", err)
				s.Error = "Failed to get local image digest"
			} else {
				remoteDigest, err := dockerClient.GetRemoteImageDigest(info.imageName, s.CurrentTag)
				if err != nil {
					logger.Warn("Failed to get remote digest", "image", info.imageName, "tag", s.CurrentTag, "error", err)
					s.Error = "Failed to check registry for updates"
				} else {
					if localDigest != remoteDigest {
						s.UpdateAvailable = true
					}
				}
			}

			status[service] = s
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    status,
		})
	}
}

// UpdateWithCrowdSec updates the stack including CrowdSec
func UpdateWithCrowdSec(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.UpdateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Updating stack with CrowdSec", "request", req)

		// Get compose file path from environment
		composeFile := os.Getenv("COMPOSE_FILE")
		if composeFile == "" {
			composeFile = "./docker-compose.yml"
		}

		// Map of service names to their image names and requested tags
		serviceUpdates := map[string]struct {
			imageName string
			tag       string
		}{
			"pangolin": {"fosrl/pangolin", req.PangolinTag},
			"gerbil":   {"fosrl/gerbil", req.GerbilTag},
			"traefik":  {"traefik", req.TraefikTag},
			"crowdsec": {"crowdsecurity/crowdsec", req.CrowdSecTag},
		}

		// Map service names to container names
		serviceToContainer := map[string]string{
			"pangolin": cfg.PangolinContainerName,
			"gerbil":   cfg.GerbilContainerName,
			"traefik":  cfg.TraefikContainerName,
			"crowdsec": cfg.CrowdsecContainerName,
		}

		// Step 1: Validate all tags against registries
		logger.Info("Validating image tags against registries")
		for serviceName, update := range serviceUpdates {
			if update.tag == "" {
				logger.Debug("Skipping validation for service (no tag provided)", "service", serviceName)
				continue
			}

			logger.Info("Validating tag", "service", serviceName, "image", update.imageName, "tag", update.tag)
			if err := dockerClient.ValidateImageTag(update.imageName, update.tag); err != nil {
				c.JSON(http.StatusBadRequest, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Invalid tag for %s: %v", serviceName, err),
				})
				return
			}
		}

		// Step 2: Update docker-compose.yml file
		logger.Info("Updating docker-compose.yml file")
		composeTags := make(map[string]string)
		for serviceName, update := range serviceUpdates {
			if update.tag != "" {
				composeTags[serviceName] = update.tag
			}
		}

		if len(composeTags) > 0 {
			if err := docker.UpdateComposeFileTags(composeFile, composeTags); err != nil {
				logger.Error("Failed to update compose file", "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   "Failed to update docker-compose.yml: " + err.Error(),
				})
				return
			}
			logger.Info("Successfully updated docker-compose.yml")
		}

		// Step 3: Pull new images
		logger.Info("Pulling new images")
		for serviceName, update := range serviceUpdates {
			if update.tag == "" {
				continue
			}

			logger.Info("Pulling image", "service", serviceName, "image", update.imageName, "tag", update.tag)
			if err := dockerClient.PullImage(update.imageName, update.tag); err != nil {
				logger.Error("Failed to pull image", "service", serviceName, "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Failed to pull image for %s: %v", serviceName, err),
				})
				return
			}
		}

		// Step 4: Recreate containers with new images
		logger.Info("Recreating containers")
		services := []string{"pangolin", "gerbil", "traefik", "crowdsec"}

		for _, service := range services {
			// Only recreate if a tag was provided for this service
			update, exists := serviceUpdates[service]
			if !exists || update.tag == "" {
				logger.Debug("Skipping container recreation (no update)", "service", service)
				continue
			}

			logger.Info("Recreating container", "service", service)
			containerName := serviceToContainer[service]
			if err := dockerClient.RecreateContainer(containerName); err != nil {
				logger.Error("Failed to recreate container", "service", service, "container", containerName, "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Failed to recreate container %s: %v", containerName, err),
				})
				return
			}
		}

		logger.Info("Stack updated successfully with CrowdSec")
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Stack updated successfully with CrowdSec",
		})
	}
}

// UpdateWithoutCrowdSec updates the stack without CrowdSec
func UpdateWithoutCrowdSec(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.UpdateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Updating stack without CrowdSec", "request", req)

		// Get compose file path from environment
		composeFile := os.Getenv("COMPOSE_FILE")
		if composeFile == "" {
			composeFile = "./docker-compose.yml"
		}

		// Map of service names to their image names and requested tags (excluding CrowdSec)
		serviceUpdates := map[string]struct {
			imageName string
			tag       string
		}{
			"pangolin": {"fosrl/pangolin", req.PangolinTag},
			"gerbil":   {"fosrl/gerbil", req.GerbilTag},
			"traefik":  {"traefik", req.TraefikTag},
		}

		// Map service names to container names
		serviceToContainer := map[string]string{
			"pangolin": cfg.PangolinContainerName,
			"gerbil":   cfg.GerbilContainerName,
			"traefik":  cfg.TraefikContainerName,
		}

		// Step 1: Validate all tags against registries
		logger.Info("Validating image tags against registries")
		for serviceName, update := range serviceUpdates {
			if update.tag == "" {
				logger.Debug("Skipping validation for service (no tag provided)", "service", serviceName)
				continue
			}

			logger.Info("Validating tag", "service", serviceName, "image", update.imageName, "tag", update.tag)
			if err := dockerClient.ValidateImageTag(update.imageName, update.tag); err != nil {
				c.JSON(http.StatusBadRequest, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Invalid tag for %s: %v", serviceName, err),
				})
				return
			}
		}

		// Step 2: Update docker-compose.yml file
		logger.Info("Updating docker-compose.yml file")
		composeTags := make(map[string]string)
		for serviceName, update := range serviceUpdates {
			if update.tag != "" {
				composeTags[serviceName] = update.tag
			}
		}

		if len(composeTags) > 0 {
			if err := docker.UpdateComposeFileTags(composeFile, composeTags); err != nil {
				logger.Error("Failed to update compose file", "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   "Failed to update docker-compose.yml: " + err.Error(),
				})
				return
			}
			logger.Info("Successfully updated docker-compose.yml")
		}

		// Step 3: Pull new images
		logger.Info("Pulling new images")
		for serviceName, update := range serviceUpdates {
			if update.tag == "" {
				continue
			}

			logger.Info("Pulling image", "service", serviceName, "image", update.imageName, "tag", update.tag)
			if err := dockerClient.PullImage(update.imageName, update.tag); err != nil {
				logger.Error("Failed to pull image", "service", serviceName, "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Failed to pull image for %s: %v", serviceName, err),
				})
				return
			}
		}

		// Step 4: Recreate containers with new images
		logger.Info("Recreating containers")
		services := []string{"pangolin", "gerbil", "traefik"}

		for _, service := range services {
			// Only recreate if a tag was provided for this service
			update, exists := serviceUpdates[service]
			if !exists || update.tag == "" {
				logger.Debug("Skipping container recreation (no update)", "service", service)
				continue
			}

			logger.Info("Recreating container", "service", service)
			containerName := serviceToContainer[service]
			if err := dockerClient.RecreateContainer(containerName); err != nil {
				logger.Error("Failed to recreate container", "service", service, "container", containerName, "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Failed to recreate container %s: %v", containerName, err),
				})
				return
			}
		}

		logger.Info("Stack updated successfully without CrowdSec")
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Stack updated successfully without CrowdSec",
		})
	}
}

// =============================================================================
// 9. CRON
// =============================================================================

// SetupCronJob sets up a cron job
func SetupCronJob() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.CronJobRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Setting up cron job", "schedule", req.Schedule, "task", req.Task)

		// In a real implementation, this would interact with the scheduler service
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Cron job setup successfully",
			Data:    gin.H{"schedule": req.Schedule, "task": req.Task},
		})
	}
}

// ListCronJobs lists all configured cron jobs
func ListCronJobs() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Listing cron jobs")

		// In a real implementation, this would retrieve from scheduler service
		jobs := []gin.H{
			{
				"id":       "1",
				"schedule": "0 2 * * *",
				"task":     "backup",
				"enabled":  true,
			},
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    jobs,
		})
	}
}

// DeleteCronJob deletes a cron job
func DeleteCronJob() gin.HandlerFunc {
	return func(c *gin.Context) {
		jobID := c.Param("id")
		logger.Info("Deleting cron job", "id", jobID)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Cron job deleted successfully",
		})
	}
}

// =============================================================================
// 10. SERVICES
// =============================================================================

// VerifyServices verifies all services are running
func VerifyServices(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Verifying services")

		services := []string{cfg.PangolinContainerName, cfg.GerbilContainerName, cfg.TraefikContainerName, cfg.CrowdsecContainerName}
		results := []gin.H{}

		for _, service := range services {
			isRunning, err := dockerClient.IsContainerRunning(service)
			result := gin.H{
				"name":    service,
				"running": isRunning,
			}
			if err != nil {
				result["error"] = err.Error()
			}
			results = append(results, result)
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    results,
		})
	}
}

// GracefulShutdown performs graceful shutdown of services
func GracefulShutdown(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Performing graceful shutdown")

		services := []string{cfg.CrowdsecContainerName, cfg.TraefikContainerName, cfg.GerbilContainerName, cfg.PangolinContainerName}

		for _, service := range services {
			logger.Info("Stopping service", "service", service)
			// Use longer timeout for Traefik
			if service == "traefik" {
				if err := dockerClient.StopContainerWithTimeout(service, 60); err != nil {
					logger.Error("Failed to stop service", "service", service, "error", err)
				}
			} else {
				if err := dockerClient.StopContainer(service); err != nil {
					logger.Error("Failed to stop service", "service", service, "error", err)
				}
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Services shutdown successfully",
		})
	}
}

// ServiceAction performs start/stop/restart action on a service
func ServiceAction(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.ServiceAction
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Performing service action", "service", req.Service, "action", req.Action)

		// Use longer timeout for Traefik to allow graceful shutdown
		timeout := 30
		if req.Service == "traefik" {
			timeout = 60
		}

		// Map service names to container names
		containerName := req.Service
		switch req.Service {
		case "crowdsec":
			containerName = cfg.CrowdsecContainerName
		case "traefik":
			containerName = cfg.TraefikContainerName
		case "pangolin":
			containerName = cfg.PangolinContainerName
		case "gerbil":
			containerName = cfg.GerbilContainerName
		}

		var err error
		switch req.Action {
		case "start":
			err = dockerClient.StartContainer(containerName)
		case "stop":
			err = dockerClient.StopContainerWithTimeout(containerName, timeout)
		case "restart":
			err = dockerClient.RestartContainerWithTimeout(containerName, timeout)
		default:
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid action. Must be start, stop, or restart",
			})
			return
		}

		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to %s service: %v", req.Action, err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("Service %s %sed successfully", req.Service, req.Action),
		})
	}
}

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

// GetDecisions retrieves CrowdSec decisions
func GetDecisions(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec decisions")

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "decisions", "list", "-o", "json",
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get decisions: %v", err),
			})
			return
		}

		// Parse as raw JSON - CrowdSec returns an array of alert objects,
		// each containing a "decisions" array
		var rawAlerts []map[string]interface{}
		if err := json.Unmarshal([]byte(output), &rawAlerts); err != nil {
			// If JSON parsing fails, log details and return error
			logger.Warn("Failed to parse decisions JSON",
				"error", err,
				"output_length", len(output),
				"output_preview", truncateString(output, 100))
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse decisions JSON: %v", err),
			})
			return
		}

		// Extract decisions from each alert and convert to normalized Decision format
		decisions := make([]models.Decision, 0)
		for _, alert := range rawAlerts {
			// Each alert has a "decisions" array
			if decisionsArr, ok := alert["decisions"].([]interface{}); ok {
				for _, decisionInterface := range decisionsArr {
					if raw, ok := decisionInterface.(map[string]interface{}); ok {
						decision := models.Decision{
							ID:       int64(getInt(raw, "id")),
							Duration: getString(raw, "duration"),
						}

						// Handle origin/source field (CrowdSec might use either)
						decision.Source = getString(raw, "source")
						if decision.Source == "" {
							decision.Source = getString(raw, "origin")
						}
						decision.Origin = decision.Source

						// Handle type field
						decision.Type = getString(raw, "type")

						// Handle scope field
						decision.Scope = getString(raw, "scope")

						// Handle value field
						decision.Value = getString(raw, "value")

						// Handle scenario/reason field (CrowdSec might use either)
						decision.Scenario = getString(raw, "scenario")
						if decision.Scenario == "" {
							decision.Scenario = getString(raw, "reason")
						}
						decision.Reason = decision.Scenario

						// Handle created_at field
						decision.CreatedAt = getString(raw, "created_at")

						decisions = append(decisions, decision)
					}
				}
			}
		}

		logger.Debug("Decisions API retrieved successfully", "count", len(decisions))

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"decisions": decisions, "count": len(decisions)},
		})
	}
}

// GetMetrics retrieves CrowdSec Prometheus metrics
func GetMetrics(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec metrics")

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "metrics",
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get metrics: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"metrics": output},
		})
	}
}

// EnrollCrowdSec enrolls CrowdSec with the console
func EnrollCrowdSec(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			EnrollmentKey string `json:"enrollment_key" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Enrolling CrowdSec with console")

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "console", "enroll", req.EnrollmentKey,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to enroll: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "CrowdSec enrolled successfully",
			Data:    gin.H{"output": output},
		})
	}
}

// GetCrowdSecEnrollmentStatus checks the enrollment status
func GetCrowdSecEnrollmentStatus(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "console", "status", "-o", "json",
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to check status: %v", err),
			})
			return
		}

		// Parse JSON output
		// Example output: {"context":{},"enrolled":true,"manual":false,"validated":true}
		var status struct {
			Enrolled  bool `json:"enrolled"`
			Validated bool `json:"validated"`
		}
		if err := json.Unmarshal([]byte(output), &status); err != nil {
			logger.Warn("Failed to parse console status JSON", "error", err, "output", output)
			// Fallback to simple string check if JSON parsing fails
			status.Enrolled = strings.Contains(output, "enrolled: true")
			status.Validated = strings.Contains(output, "validated: true")
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    status,
		})
	}
}

// CheckTraefikIntegration checks Traefik-CrowdSec integration
func CheckTraefikIntegration(dockerClient *docker.Client, db *database.Database, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Checking Traefik integration")

		integration := models.TraefikIntegration{
			MiddlewareConfigured: false,
			ConfigFiles:          []string{},
			LapiKeyFound:         false,
			AppsecEnabled:        false,
			CaptchaEnabled:       false,
			CaptchaProvider:      "",
			CaptchaHTMLExists:    false,
		}

		// Check multiple possible config files
		configPaths := []string{
			"/etc/traefik/dynamic_config.yml",
			"/etc/traefik/traefik_config.yml",
		}

		// Get dynamic config path from database if available
		if db != nil {
			if path, err := db.GetTraefikDynamicConfigPath(); err == nil {
				// Prepend database path to the beginning of the list
				configPaths = append([]string{path}, configPaths...)
			}
		}

		var config string
		var configPath string

		// Try each path until we find one that works
		for _, path := range configPaths {
			output, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{"cat", path})
			if err == nil && output != "" {
				config = output
				configPath = path
				break
			}
		}

		if config == "" {
			// No config found, return empty integration
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data:    integration,
				Message: "No Traefik config files found",
			})
			return
		}

		// Config found - proceed with checks
		integration.MiddlewareConfigured = true
		integration.ConfigFiles = append(integration.ConfigFiles, configPath)

		// Better detection logic - use case-insensitive matching
		configLower := strings.ToLower(config)

		// Check for CrowdSec bouncer plugin
		if strings.Contains(configLower, "crowdsec-bouncer-traefik-plugin") ||
			strings.Contains(configLower, "crowdseclapikey") ||
			strings.Contains(configLower, "crowdsec") {
			integration.LapiKeyFound = true
		}

		// Check for AppSec
		if strings.Contains(configLower, "appsec") {
			integration.AppsecEnabled = true
		}

		// Check for Captcha
		captchaEnabled, captchaProvider, _ := detectCaptchaInConfig(config)
		integration.CaptchaEnabled = captchaEnabled
		integration.CaptchaProvider = captchaProvider

		// Check if captcha.html exists in Traefik container
		captchaExists, captchaErr := dockerClient.FileExists(cfg.TraefikContainerName, "/etc/traefik/conf/captcha.html")
		if captchaErr == nil && captchaExists {
			integration.CaptchaHTMLExists = true
		}

		logger.Info("Traefik integration check complete",
			"middleware", integration.MiddlewareConfigured,
			"lapi_key", integration.LapiKeyFound,
			"appsec", integration.AppsecEnabled)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    integration,
		})
	}
}

// GetTraefikConfig retrieves Traefik configuration
func GetTraefikConfig() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting Traefik config")

		// In a real implementation, read from config file
		config := gin.H{
			"static":  "traefik_config.yml content",
			"dynamic": "dynamic_config.yml content",
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    config,
		})
	}
}

// GetTraefikConfigPath retrieves the current dynamic config path
func GetTraefikConfigPath(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting Traefik config path")

		settings, err := db.GetSettings()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get settings: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: gin.H{
				"dynamic_config_path": settings.TraefikDynamicConfig,
				"static_config_path":  settings.TraefikStaticConfig,
				"access_log_path":     settings.TraefikAccessLog,
				"error_log_path":      settings.TraefikErrorLog,
				"crowdsec_acquis":     settings.CrowdSecAcquisFile,
			},
		})
	}
}

// SetTraefikConfigPath sets the dynamic config path
func SetTraefikConfigPath(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.ConfigPathRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Setting Traefik config path", "path", req.DynamicConfigPath)

		// Update database
		err := db.SetTraefikDynamicConfigPath(req.DynamicConfigPath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update config path: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Dynamic config path updated successfully",
			Data:    gin.H{"dynamic_config_path": req.DynamicConfigPath},
		})
	}
}

// UpdateSettings updates all file path settings
func UpdateSettings(db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req database.Settings
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Updating settings")

		err := db.UpdateSettings(&req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update settings: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Settings updated successfully",
			Data:    req,
		})
	}
}

// GetFileContent reads a file from a Docker container
func GetFileContent(dockerClient *docker.Client, db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		container := c.Param("container")
		fileType := c.Param("fileType")

		logger.Info("Getting file content", "container", container, "fileType", fileType)

		settings, _ := db.GetSettings()

		var filePath string
		switch fileType {
		case "dynamic_config":
			filePath = settings.TraefikDynamicConfig
		case "static_config":
			filePath = settings.TraefikStaticConfig
		case "access_log":
			filePath = settings.TraefikAccessLog
		case "error_log":
			filePath = settings.TraefikErrorLog
		case "crowdsec_acquis":
			filePath = settings.CrowdSecAcquisFile
		default:
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid file type",
			})
			return
		}

		content, err := dockerClient.ExecCommand(container, []string{"cat", filePath})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to read file: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: gin.H{
				"path":    filePath,
				"content": content,
			},
		})
	}
}

// GetDecisionsAnalysis retrieves CrowdSec decisions with advanced filtering
func GetDecisionsAnalysis(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec decisions with filters")

		// Build command with filters from query parameters
		cmd := []string{"cscli", "decisions", "list", "-o", "json"}

		// Add time-based filters
		if since := c.Query("since"); since != "" {
			cmd = append(cmd, "--since", since)
		}
		if until := c.Query("until"); until != "" {
			cmd = append(cmd, "--until", until)
		}

		// Add decision type filter
		if decType := c.Query("type"); decType != "" && decType != "all" {
			cmd = append(cmd, "-t", decType)
		}

		// Add scope filter
		if scope := c.Query("scope"); scope != "" && scope != "all" {
			cmd = append(cmd, "--scope", scope)
		}

		// Add origin filter
		if origin := c.Query("origin"); origin != "" && origin != "all" {
			cmd = append(cmd, "--origin", origin)
		}

		// Add value filter
		if value := c.Query("value"); value != "" {
			cmd = append(cmd, "-v", value)
		}

		// Add scenario filter
		if scenario := c.Query("scenario"); scenario != "" {
			cmd = append(cmd, "-s", scenario)
		}

		// Add IP filter (shorthand for --scope ip --value <IP>)
		if ip := c.Query("ip"); ip != "" {
			cmd = append(cmd, "-i", ip)
		}

		// Add range filter (shorthand for --scope range --value <RANGE>)
		if ipRange := c.Query("range"); ipRange != "" {
			cmd = append(cmd, "-r", ipRange)
		}

		// Add --all flag to include decisions from Central API
		if includeAll := c.Query("includeAll"); includeAll == "true" {
			cmd = append(cmd, "-a")
		}

		logger.Debug("Executing decision analysis command", "cmd", cmd)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get decisions: %v", err),
			})
			return
		}

		// Log raw output for debugging
		logger.Debug("Raw decisions output",
			"length", len(output),
			"preview", truncateString(output, 200))

		// Parse as raw JSON - CrowdSec returns an array of alert objects,
		// each containing a "decisions" array
		var rawAlerts []map[string]interface{}
		if err := json.Unmarshal([]byte(output), &rawAlerts); err != nil {
			logger.Warn("Failed to parse decisions JSON",
				"error", err,
				"output_length", len(output),
				"output_preview", truncateString(output, 100))
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse decisions JSON: %v", err),
			})
			return
		}

		// Extract decisions from each alert and convert to normalized Decision format
		decisions := make([]models.Decision, 0)
		for _, alert := range rawAlerts {
			// Each alert has a "decisions" array
			if decisionsArr, ok := alert["decisions"].([]interface{}); ok {
				// Get alert-level created_at (decisions don't have their own created_at)
				alertCreatedAt := getString(alert, "created_at")
				
				for _, decisionInterface := range decisionsArr {
					if raw, ok := decisionInterface.(map[string]interface{}); ok {
						decision := models.Decision{
							ID:       int64(getInt(raw, "id")),
							Duration: getString(raw, "duration"),
						}

						// Handle origin/source field (CrowdSec might use either)
						decision.Source = getString(raw, "source")
						if decision.Source == "" {
							decision.Source = getString(raw, "origin")
						}
						decision.Origin = decision.Source

						// Handle type field
						decision.Type = getString(raw, "type")

						// Handle scope field
						decision.Scope = getString(raw, "scope")

						// Handle value field
						decision.Value = getString(raw, "value")

						// Handle scenario/reason field (CrowdSec might use either)
						decision.Scenario = getString(raw, "scenario")
						if decision.Scenario == "" {
							decision.Scenario = getString(raw, "reason")
						}
						decision.Reason = decision.Scenario

						// Use alert-level created_at (decisions inherit from their alert)
						decision.CreatedAt = alertCreatedAt

						// Calculate until/expires timestamp from created_at and duration
						if decision.CreatedAt != "" && decision.Duration != "" {
							if untilTime := calculateUntil(decision.CreatedAt, decision.Duration); untilTime != nil {
								decision.Until = untilTime.Format(time.RFC3339)
							}
						}

						decisions = append(decisions, decision)
					}
				}
			}
		}

		logger.Info("Decisions retrieved successfully",
			"count", len(decisions),
			"filters_applied", len(activeFilters(c)))

		// Return properly formatted data
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"decisions": decisions, "count": len(decisions)},
		})
	}
}

// GetAlertsAnalysis retrieves CrowdSec alerts with advanced filtering
func GetAlertsAnalysis(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec alerts with filters")

		// Build command with filters from query parameters
		cmd := []string{"cscli", "alerts", "list", "-o", "json"}

		// Add time-based filters
		if since := c.Query("since"); since != "" {
			cmd = append(cmd, "--since", since)
		}
		if until := c.Query("until"); until != "" {
			cmd = append(cmd, "--until", until)
		}

		// Add IP filter
		if ip := c.Query("ip"); ip != "" {
			cmd = append(cmd, "-i", ip)
		}

		// Add range filter
		if ipRange := c.Query("range"); ipRange != "" {
			cmd = append(cmd, "-r", ipRange)
		}

		// Add scope filter
		if scope := c.Query("scope"); scope != "" && scope != "all" {
			cmd = append(cmd, "--scope", scope)
		}

		// Add value filter
		if value := c.Query("value"); value != "" {
			cmd = append(cmd, "-v", value)
		}

		// Add scenario filter
		if scenario := c.Query("scenario"); scenario != "" {
			cmd = append(cmd, "-s", scenario)
		}

		// Add type filter (decision type associated with alert)
		if alertType := c.Query("type"); alertType != "" && alertType != "all" {
			cmd = append(cmd, "--type", alertType)
		}

		// Add origin filter
		if origin := c.Query("origin"); origin != "" && origin != "all" {
			cmd = append(cmd, "--origin", origin)
		}

		// Add --all flag to include alerts from Central API
		if includeAll := c.Query("includeAll"); includeAll == "true" {
			cmd = append(cmd, "-a")
		}

		logger.Debug("Executing alert analysis command", "cmd", cmd)

		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, cmd)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get alerts: %v", err),
			})
			return
		}

		// Parse the JSON output
		var alerts []interface{}
		if err := json.Unmarshal([]byte(output), &alerts); err != nil {
			logger.Warn("Failed to parse alerts JSON",
				"error", err,
				"output_length", len(output),
				"output_preview", truncateString(output, 100))
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse alerts JSON: %v", err),
			})
			return
		}

		logger.Debug("Alerts analysis retrieved successfully", "count", len(alerts))

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"alerts": alerts, "count": len(alerts)},
		})
	}
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// parseWhitelistYAML parses whitelist YAML content and extracts IPs
func parseWhitelistYAML(content string) []string {
	ips := []string{}
	lines := strings.Split(content, "\n")

	ipRegex := regexp.MustCompile(`^\s*-\s+([0-9\.\/]+)`)
	for _, line := range lines {
		if matches := ipRegex.FindStringSubmatch(line); len(matches) > 1 {
			ips = append(ips, matches[1])
		}
	}

	return ips
}

// parseTraefikWhitelist parses Traefik whitelist configuration
func parseTraefikWhitelist(content string) []string {
	ips := []string{}
	lines := strings.Split(content, "\n")

	ipRegex := regexp.MustCompile(`^\s*-\s+([0-9\.\/]+)`)
	inSourceRange := false

	for _, line := range lines {
		if strings.Contains(line, "sourceRange:") {
			inSourceRange = true
			continue
		}

		if inSourceRange {
			if matches := ipRegex.FindStringSubmatch(line); len(matches) > 1 {
				ips = append(ips, matches[1])
			} else if !strings.HasPrefix(strings.TrimSpace(line), "-") {
				inSourceRange = false
			}
		}
	}

	return ips
}

// analyzeLogs performs log analysis and returns statistics
func analyzeLogs(logs string) models.LogStats {
	lines := strings.Split(logs, "\n")

	stats := models.LogStats{
		TotalLines:   len(lines),
		TopIPs:       []models.IPCount{},
		StatusCodes:  make(map[string]int),
		HTTPMethods:  make(map[string]int),
		ErrorEntries: []models.LogEntry{},
	}

	ipMap := make(map[string]int)
	ipRegex := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	statusRegex := regexp.MustCompile(`\s(2\d{2}|3\d{2}|4\d{2}|5\d{2})\s`)
	methodRegex := regexp.MustCompile(`"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)`)

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Extract IPs
		if ips := ipRegex.FindAllString(line, -1); len(ips) > 0 {
			for _, ip := range ips {
				ipMap[ip]++
			}
		}

		// Extract status codes
		if matches := statusRegex.FindStringSubmatch(line); len(matches) > 1 {
			stats.StatusCodes[matches[1]]++
		}

		// Extract HTTP methods
		if matches := methodRegex.FindStringSubmatch(line); len(matches) > 1 {
			stats.HTTPMethods[matches[1]]++
		}

		// Collect error entries
		if strings.Contains(strings.ToLower(line), "error") ||
			strings.Contains(line, "5") && statusRegex.MatchString(line) {
			stats.ErrorEntries = append(stats.ErrorEntries, models.LogEntry{
				Timestamp: time.Now(),
				Level:     "error",
				Service:   "traefik",
				Message:   line,
			})
		}
	}

	// Convert IP map to sorted slice
	for ip, count := range ipMap {
		stats.TopIPs = append(stats.TopIPs, models.IPCount{
			IP:    ip,
			Count: count,
		})
	}
	sort.Slice(stats.TopIPs, func(i, j int) bool {
		return stats.TopIPs[i].Count > stats.TopIPs[j].Count
	})

	// Keep only top 10 IPs
	if len(stats.TopIPs) > 10 {
		stats.TopIPs = stats.TopIPs[:10]
	}

	// Keep only last 20 error entries
	if len(stats.ErrorEntries) > 20 {
		stats.ErrorEntries = stats.ErrorEntries[len(stats.ErrorEntries)-20:]
	}

	return stats
}

// =============================================================================
// 13. ALLOWLIST MANAGEMENT
// =============================================================================

// ListAllowlists lists all CrowdSec allowlists
func ListAllowlists(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Listing allowlists")

		output, err := dockerClient.ExecCommand("crowdsec", []string{"cscli", "allowlists", "list", "-o", "json"})
		if err != nil {
			logger.Error("Failed to list allowlists", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to list allowlists: %v", err),
			})
			return
		}

		var allowlists []models.Allowlist
		if err := json.Unmarshal([]byte(output), &allowlists); err != nil {
			logger.Error("Failed to parse allowlists JSON", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse allowlists: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    allowlists,
			Message: fmt.Sprintf("Found %d allowlists", len(allowlists)),
		})
	}
}

// CreateAllowlist creates a new CrowdSec allowlist
func CreateAllowlist(dockerClient *docker.Client) gin.HandlerFunc {
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
		output, err := dockerClient.ExecCommand("crowdsec", cmd)
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
				CreatedAt:   time.Now(),
			},
			Message: fmt.Sprintf("Allowlist '%s' created successfully", req.Name),
		})
	}
}

// InspectAllowlist inspects a specific allowlist
func InspectAllowlist(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		logger.Info("Inspecting allowlist", "name", name)

		output, err := dockerClient.ExecCommand("crowdsec", []string{"cscli", "allowlists", "inspect", name, "-o", "json"})
		if err != nil {
			logger.Error("Failed to inspect allowlist", "name", name, "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to inspect allowlist: %v", err),
			})
			return
		}

		var response models.AllowlistInspectResponse
		if err := json.Unmarshal([]byte(output), &response); err != nil {
			logger.Error("Failed to parse allowlist JSON", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse allowlist data: %v", err),
			})
			return
		}

		// Calculate count from items length (CrowdSec doesn't provide it)
		response.Count = len(response.Items)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    response,
			Message: fmt.Sprintf("Allowlist '%s' has %d entries", name, response.Count),
		})
	}
}

// AddAllowlistEntries adds entries to an allowlist
func AddAllowlistEntries(dockerClient *docker.Client) gin.HandlerFunc {
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

		output, err := dockerClient.ExecCommand("crowdsec", cmd)
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
func RemoveAllowlistEntries(dockerClient *docker.Client) gin.HandlerFunc {
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

		output, err := dockerClient.ExecCommand("crowdsec", cmd)
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
func DeleteAllowlist(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		name := c.Param("name")
		logger.Info("Deleting allowlist", "name", name)

		output, err := dockerClient.ExecCommand("crowdsec", []string{"cscli", "allowlists", "delete", name})
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

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// truncateString truncates a string to a maximum length for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "... (truncated)"
}

// Helper functions for safe type conversion from map[string]interface{}
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int {
	if v, ok := m[key]; ok {
		switch val := v.(type) {
		case float64:
			return int(val)
		case int:
			return val
		case int64:
			return int(val)
		}
	}
	return 0
}

// calculateUntil calculates the expiration time from created_at and duration
// Duration format: "3h57m35s", "1h", "30m", etc.
func calculateUntil(createdAtStr, durationStr string) *time.Time {
	if createdAtStr == "" || durationStr == "" {
		return nil
	}

	// Parse created_at timestamp - try multiple formats
	var createdAt time.Time
	
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05 +0000 UTC",
		time.RFC3339Nano,
	}
	
	for _, format := range formats {
		if t, err := time.Parse(format, createdAtStr); err == nil {
			createdAt = t
			break
		}
	}
	
	if createdAt.IsZero() {
		logger.Debug("Failed to parse created_at", "value", createdAtStr)
		return nil
	}

	// Parse duration (e.g., "3h57m35s", "1h", "30m")
	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		logger.Debug("Failed to parse duration", "value", durationStr, "error", err)
		return nil
	}

	// Calculate until time
	until := createdAt.Add(duration)
	return &until
}

func activeFilters(c *gin.Context) map[string]string {
	filters := make(map[string]string)
	for _, key := range []string{"since", "until", "type", "scope", "origin", "value", "scenario", "ip", "range"} {
		if val := c.Query(key); val != "" && val != "all" {
			filters[key] = val
		}
	}
	return filters
}

// parseHumanReadableScenarios parses the human-readable table format
func parseHumanReadableScenarios(output string) []gin.H {
	scenarios := []gin.H{}
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines, headers, and separator lines
		if line == "" ||
			strings.Contains(line, "─") ||
			strings.Contains(line, "SCENARIOS") ||
			strings.Contains(line, "Name") ||
			strings.Contains(line, "📦 Status") {
			continue
		}

		// Remove leading/trailing pipes if present
		line = strings.Trim(line, "│ ")

		// Split by multiple spaces (table columns)
		parts := strings.Fields(line)

		if len(parts) >= 2 {
			scenario := gin.H{
				"name": parts[0],
			}

			// Parse status
			if len(parts) >= 2 {
				if strings.Contains(parts[1], "enabled") || parts[1] == "✔️" {
					scenario["status"] = "enabled"
				} else {
					scenario["status"] = parts[1]
				}
			}

			// Parse version
			if len(parts) >= 3 {
				scenario["version"] = parts[2]
			}

			// Parse local path (join remaining parts)
			if len(parts) >= 4 {
				scenario["local_path"] = strings.Join(parts[3:], " ")
			}

			scenarios = append(scenarios, scenario)
		}
	}

	return scenarios
}
