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
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// =============================================================================
// 1. HEALTH & DIAGNOSTICS
// =============================================================================

// CheckStackHealth checks the health of all containers in the stack
func CheckStackHealth(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Checking stack health")

		containerNames := []string{"crowdsec", "traefik", "pangolin", "gerbil"}
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
func RunCompleteDiagnostics(dockerClient *docker.Client, db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Running complete diagnostics")

		// Get health status
		containerNames := []string{"crowdsec", "traefik", "pangolin", "gerbil"}
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
		bouncerOutput, err := dockerClient.ExecCommand("crowdsec", []string{"cscli", "bouncers", "list", "-o", "json"})
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
					if bouncers[i].Valid {
						bouncers[i].Status = "connected"
					} else {
						bouncers[i].Status = "disconnected"
					}

					// Check if last pull was recent (within 5 minutes)
					if time.Since(bouncers[i].LastPull) > 5*time.Minute {
						bouncers[i].Status = "stale"
					}
				}
				logger.Debug("Bouncers retrieved successfully", "count", len(bouncers))
			}
		} else {
			logger.Warn("Failed to execute bouncers command", "error", err)
		}

		// Get decisions
		var decisions []models.Decision
		decisionOutput, err := dockerClient.ExecCommand("crowdsec", []string{"cscli", "decisions", "list", "-o", "json"})
		if err == nil {
			if err := json.Unmarshal([]byte(decisionOutput), &decisions); err != nil {
				logger.Warn("Failed to parse decisions JSON",
					"error", err,
					"output_length", len(decisionOutput),
					"output_preview", truncateString(decisionOutput, 100))
			} else {
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
			output, err := dockerClient.ExecCommand("traefik", []string{"cat", path})
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
func IsIPBlocked(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.Param("ip")
		logger.Info("Checking if IP is blocked", "ip", ip)

		// Check CrowdSec decisions
		output, err := dockerClient.ExecCommand("crowdsec", []string{
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
func CheckIPSecurity(dockerClient *docker.Client) gin.HandlerFunc {
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
		decisionOutput, err := dockerClient.ExecCommand("crowdsec", []string{
			"cscli", "decisions", "list", "-i", ip,
		})
		if err == nil {
			ipInfo.IsBlocked = strings.Contains(decisionOutput, ip) &&
				strings.Contains(decisionOutput, "ban")
		}

		// Check CrowdSec whitelist
		whitelistOutput, err := dockerClient.ExecCommand("crowdsec", []string{
			"cat", "/etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml",
		})
		if err == nil {
			ipInfo.InCrowdSec = strings.Contains(whitelistOutput, ip)
			if ipInfo.InCrowdSec {
				ipInfo.IsWhitelisted = true
			}
		}

		// Check Traefik whitelist
		traefikConfig, err := dockerClient.ExecCommand("traefik", []string{
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
func UnbanIP(dockerClient *docker.Client) gin.HandlerFunc {
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
		output, err := dockerClient.ExecCommand("crowdsec", []string{
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
func ViewWhitelist(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Viewing whitelist")

		whitelist := gin.H{
			"crowdsec": []string{},
			"traefik":  []string{},
		}

		// Get CrowdSec whitelist
		crowdsecWL, err := dockerClient.ExecCommand("crowdsec", []string{
			"cat", "/etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml",
		})
		if err == nil {
			whitelist["crowdsec"] = parseWhitelistYAML(crowdsecWL)
		}

		// Get Traefik whitelist
		traefikWL, err := dockerClient.ExecCommand("traefik", []string{
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
func WhitelistCurrentIP(dockerClient *docker.Client) gin.HandlerFunc {
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
		_, err = dockerClient.ExecCommand("crowdsec", []string{
			"sh", "-c", fmt.Sprintf("echo '%s' > /etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml", whitelistContent),
		})
		if err != nil {
			logger.Error("Failed to update CrowdSec whitelist", "error", err)
		}

		// Reload CrowdSec
		_, _ = dockerClient.ExecCommand("crowdsec", []string{"cscli", "parsers", "reload"})

		logger.Info("Current IP whitelisted", "ip", publicIP)
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("IP %s has been whitelisted", publicIP),
			Data:    gin.H{"ip": publicIP},
		})
	}
}

// WhitelistManualIP whitelists a manually specified IP
func WhitelistManualIP(dockerClient *docker.Client) gin.HandlerFunc {
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
			currentWL, err := dockerClient.ExecCommand("crowdsec", []string{
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

			_, err = dockerClient.ExecCommand("crowdsec", []string{
				"sh", "-c", fmt.Sprintf("echo '%s' > /etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml", whitelistContent),
			})
			if err != nil {
				errMsg := fmt.Sprintf("Failed to add IP to CrowdSec whitelist: %v", err)
				logger.Error(errMsg, "error", err)
				errors = append(errors, errMsg)
			} else {
				// Reload parsers to apply changes
				if _, reloadErr := dockerClient.ExecCommand("crowdsec", []string{"cscli", "parsers", "reload"}); reloadErr != nil {
					logger.Warn("Failed to reload CrowdSec parsers", "error", reloadErr)
					successMessages = append(successMessages, "Added to CrowdSec whitelist (reload failed, restart CrowdSec to apply)")
				} else {
					successMessages = append(successMessages, "Added to CrowdSec whitelist")
				}
			}
		}

		if req.AddToTraefik {
			// Update Traefik dynamic config
			_, err := dockerClient.ExecCommand("traefik", []string{
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
func WhitelistCIDR(dockerClient *docker.Client) gin.HandlerFunc {
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

			_, err := dockerClient.ExecCommand("crowdsec", []string{
				"sh", "-c", fmt.Sprintf("echo '%s' > /etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml", whitelistContent),
			})
			if err != nil {
				logger.Error("Failed to update CrowdSec whitelist", "error", err)
			} else {
				_, _ = dockerClient.ExecCommand("crowdsec", []string{"cscli", "parsers", "reload"})
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("CIDR %s has been whitelisted", req.CIDR),
		})
	}
}

// AddToCrowdSecWhitelist adds an IP to CrowdSec whitelist only
func AddToCrowdSecWhitelist(dockerClient *docker.Client) gin.HandlerFunc {
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

		_, err := dockerClient.ExecCommand("crowdsec", []string{
			"sh", "-c", fmt.Sprintf("echo '%s' > /etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml", whitelistContent),
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update whitelist: %v", err),
			})
			return
		}

		_, _ = dockerClient.ExecCommand("crowdsec", []string{"cscli", "parsers", "reload"})

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("IP %s added to CrowdSec whitelist", req.IP),
		})
	}
}

// AddToTraefikWhitelist adds an IP to Traefik whitelist only
func AddToTraefikWhitelist(dockerClient *docker.Client) gin.HandlerFunc {
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

		_, err := dockerClient.ExecCommand("traefik", []string{
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
func SetupComprehensiveWhitelist(dockerClient *docker.Client) gin.HandlerFunc {
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

		_, err := dockerClient.ExecCommand("crowdsec", []string{
			"sh", "-c", fmt.Sprintf("echo '%s' > /etc/crowdsec/parsers/s02-enrich/mywhitelists.yaml", whitelistContent),
		})
		if err == nil {
			_, _ = dockerClient.ExecCommand("crowdsec", []string{"cscli", "parsers", "reload"})
			results["crowdsec"] = true
		}

		// Add to Traefik
		_, err = dockerClient.ExecCommand("traefik", []string{
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
func SetupCustomScenarios(dockerClient *docker.Client) gin.HandlerFunc {
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

		results := []gin.H{}
		hasErrors := false

		for _, scenario := range req.Scenarios {
			// Extract filename from scenario name (handle namespace/scenario-name format)
			filename := strings.ReplaceAll(scenario.Name, "/", "_") + ".yaml"
			scenarioPath := filepath.Join("/etc/crowdsec/scenarios", filename)

			logger.Debug("Writing scenario file", "name", scenario.Name, "path", scenarioPath)

			// Use cat with heredoc to properly write multi-line YAML content
			// This handles special characters and multi-line content correctly
			command := fmt.Sprintf("cat > %s << 'SCENARIO_EOF'\n%s\nSCENARIO_EOF", scenarioPath, scenario.Content)

			_, err := dockerClient.ExecCommand("crowdsec", []string{"sh", "-c", command})

			result := gin.H{
				"name":    scenario.Name,
				"success": err == nil,
				"path":    scenarioPath,
			}
			if err != nil {
				result["error"] = err.Error()
				hasErrors = true
				logger.Error("Failed to write scenario file", "name", scenario.Name, "error", err)
			} else {
				logger.Info("Successfully wrote scenario file", "name", scenario.Name, "path", scenarioPath)
			}
			results = append(results, result)
		}

		// Restart CrowdSec to load new scenarios
		// Note: reload doesn't work for custom scenarios, need full restart
		if !hasErrors {
			logger.Info("Restarting CrowdSec to load new scenarios")
			restartOutput, restartErr := dockerClient.ExecCommand("crowdsec", []string{"sh", "-c", "kill -SIGHUP 1"})
			if restartErr != nil {
				logger.Warn("Failed to send HUP signal to CrowdSec, attempting container restart", "error", restartErr)
				// Fallback: restart the container
				if err := dockerClient.RestartContainerWithTimeout("crowdsec", 30); err != nil {
					logger.Error("Failed to restart CrowdSec container", "error", err)
					c.JSON(http.StatusOK, models.Response{
						Success: false,
						Message: "Scenarios written but failed to restart CrowdSec",
						Data:    results,
						Error:   fmt.Sprintf("Restart failed: %v", err),
					})
					return
				}
			} else {
				logger.Debug("CrowdSec reload signal sent", "output", restartOutput)
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: !hasErrors,
			Message: "Custom scenarios setup completed",
			Data:    results,
		})
	}
}

// ListScenarios lists all installed CrowdSec scenarios
func ListScenarios(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Listing scenarios")

		// Try JSON format first
		output, err := dockerClient.ExecCommand("crowdsec", []string{
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
			"first_200_chars", truncateString(output, 200))

		// Clean the output - remove any non-JSON characters
		cleanedOutput := strings.TrimSpace(output)

		// Try to parse as JSON first
		var jsonScenarios []any
		if err := json.Unmarshal([]byte(cleanedOutput), &jsonScenarios); err == nil {
			// Successfully parsed as JSON
			logger.Info("Successfully parsed scenarios as JSON", "count", len(jsonScenarios))

			// Return with proper structure including count
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Message: fmt.Sprintf("Found %d scenarios", len(jsonScenarios)),
				Data:    gin.H{
					"scenarios": jsonScenarios,
					"count": len(jsonScenarios),
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
				Data:    gin.H{
					"scenarios": scenarios,
					"count": len(scenarios),
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
				"output_length": len(output),
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

// =============================================================================
// 5. CAPTCHA
// =============================================================================

// SetupCaptcha sets up Cloudflare Turnstile captcha
func SetupCaptcha(dockerClient *docker.Client) gin.HandlerFunc {
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

		// Store captcha configuration in environment or config file
		captchaConfig := fmt.Sprintf(`CAPTCHA_PROVIDER=%s
CAPTCHA_SITE_KEY=%s
CAPTCHA_SECRET_KEY=%s
`, req.Provider, req.SiteKey, req.SecretKey)

		// Write to config file in Traefik container
		_, err := dockerClient.ExecCommand("traefik", []string{
			"sh", "-c", fmt.Sprintf("echo '%s' > /etc/traefik/captcha.env", captchaConfig),
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to setup captcha: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Captcha configured successfully",
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
func GetCaptchaStatus(dockerClient *docker.Client, db *database.Database) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting captcha status")

		// Check if captcha.env exists (saved configuration)
		output, err := dockerClient.ExecCommand("traefik", []string{
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
		configContent, err := dockerClient.ExecCommand("traefik", []string{
			"cat", dynamicConfigPath,
		})

		configured := false
		detectedProvider := ""
		hasHTMLPath := false

		if err == nil && configContent != "" {
			configured, detectedProvider, hasHTMLPath = detectCaptchaInConfig(configContent)
		}

		// Check if captcha.html exists
		captchaHTMLExists := false
		_, htmlErr := dockerClient.ExecCommand("traefik", []string{
			"test", "-f", "/etc/traefik/captcha.html",
		})
		if htmlErr == nil {
			captchaHTMLExists = true
		}

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
			"configured":         configured,         // True if captcha is in dynamic_config.yml
			"configSaved":        configSaved,        // True if captcha.env exists
			"provider":           finalProvider,      // Detected or saved provider
			"detectedProvider":   detectedProvider,   // Provider from dynamic_config.yml
			"savedProvider":      savedProvider,      // Provider from captcha.env
			"captchaHTMLExists":  captchaHTMLExists,  // True if captcha.html exists
			"hasHTMLPath":        hasHTMLPath,        // True if captchaHTMLFilePath is configured
			"implemented":        configured && captchaHTMLExists, // Fully implemented if both exist
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
func GetCrowdSecLogs(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		tail := c.DefaultQuery("tail", "100")
		logger.Info("Getting CrowdSec logs", "tail", tail)

		logs, err := dockerClient.GetContainerLogs("crowdsec", tail)
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
func GetTraefikLogs(dockerClient *docker.Client, db *database.Database) gin.HandlerFunc {
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
		logs, err := dockerClient.ExecCommand("traefik", []string{"tail", "-n", tail, logPath})
		if err != nil {
			// Fallback to container logs if file reading fails
			logger.Warn("Failed to read log file, falling back to container logs", "error", err)
			logs, err = dockerClient.GetContainerLogs("traefik", tail)
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
func AnalyzeTraefikLogsAdvanced(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		tail := c.DefaultQuery("tail", "1000")
		logger.Info("Analyzing Traefik logs", "tail", tail)

		logs, err := dockerClient.GetContainerLogs("traefik", tail)
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
		logTicker := time.NewTicker(time.Second)
		defer logTicker.Stop()

		done := make(chan struct{})

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
					ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error checking container status: %v", err)))
					continue
				}

				if !isRunning {
					ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Container '%s' is not running (restarting or stopped)", service)))
					continue
				}

				logs, err := dockerClient.GetContainerLogs(service, "10")
				if err != nil {
					ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error fetching logs: %v", err)))
					continue
				}

				if err := ws.WriteMessage(websocket.TextMessage, []byte(logs)); err != nil {
					logger.Debug("WebSocket write error", "error", err)
					return
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

// GetCurrentTags retrieves current Docker image tags from running containers
func GetCurrentTags(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting current image tags")

		tags := models.ImageTags{
			Pangolin: "latest",
			Gerbil:   "latest",
			Traefik:  "latest",
			CrowdSec: "latest",
		}

		// Container name to field mapping
		containerMapping := map[string]*string{
			"pangolin": &tags.Pangolin,
			"gerbil":   &tags.Gerbil,
			"traefik":  &tags.Traefik,
			"crowdsec": &tags.CrowdSec,
		}

		// Inspect each container to get its actual image tag
		for containerName, tagField := range containerMapping {
			inspect, err := dockerClient.InspectContainer(containerName)
			if err != nil {
				logger.Warn("Failed to inspect container", "name", containerName, "error", err)
				continue
			}

			// Extract tag from image string
			// Image format examples:
			// - "docker.io/fosrl/pangolin:latest"
			// - "docker.io/traefik:v3.5"
			// - "crowdsecurity/crowdsec:latest"
			imageParts := strings.Split(inspect.Config.Image, ":")
			if len(imageParts) >= 2 {
				// Get the last part after the last colon (the tag)
				*tagField = imageParts[len(imageParts)-1]
			} else {
				logger.Warn("Could not parse image tag", "name", containerName, "image", inspect.Config.Image)
			}

			logger.Debug("Retrieved image tag", "container", containerName, "tag", *tagField)
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    tags,
		})
	}
}

// UpdateWithCrowdSec updates the stack including CrowdSec
func UpdateWithCrowdSec(dockerClient *docker.Client) gin.HandlerFunc {
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
			if err := dockerClient.RecreateContainer(service); err != nil {
				logger.Error("Failed to recreate container", "service", service, "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Failed to recreate container %s: %v", service, err),
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
func UpdateWithoutCrowdSec(dockerClient *docker.Client) gin.HandlerFunc {
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
			if err := dockerClient.RecreateContainer(service); err != nil {
				logger.Error("Failed to recreate container", "service", service, "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Failed to recreate container %s: %v", service, err),
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
func VerifyServices(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Verifying services")

		services := []string{"pangolin", "gerbil", "traefik", "crowdsec"}
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
func GracefulShutdown(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Performing graceful shutdown")

		services := []string{"crowdsec", "traefik", "gerbil", "pangolin"}

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
func ServiceAction(dockerClient *docker.Client) gin.HandlerFunc {
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

		var err error
		switch req.Action {
		case "start":
			err = dockerClient.StartContainer(req.Service)
		case "stop":
			err = dockerClient.StopContainerWithTimeout(req.Service, timeout)
		case "restart":
			err = dockerClient.RestartContainerWithTimeout(req.Service, timeout)
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
func GetBouncers(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec bouncers")

		output, err := dockerClient.ExecCommand("crowdsec", []string{
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
			if bouncers[i].Valid {
				bouncers[i].Status = "connected"
			} else {
				bouncers[i].Status = "disconnected"
			}

			// Check if last pull was recent (within 5 minutes)
			if time.Since(bouncers[i].LastPull) > 5*time.Minute {
				bouncers[i].Status = "stale"
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
func GetDecisions(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec decisions")

		output, err := dockerClient.ExecCommand("crowdsec", []string{
			"cscli", "decisions", "list", "-o", "json",
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get decisions: %v", err),
			})
			return
		}

		// Parse the JSON to ensure it's valid and return as structured data
		var decisions []models.Decision
		if err := json.Unmarshal([]byte(output), &decisions); err != nil {
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

		logger.Debug("Decisions API retrieved successfully", "count", len(decisions))

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"decisions": decisions, "count": len(decisions)},
		})
	}
}

// GetMetrics retrieves CrowdSec Prometheus metrics
func GetMetrics(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting CrowdSec metrics")

		output, err := dockerClient.ExecCommand("crowdsec", []string{
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
func EnrollCrowdSec(dockerClient *docker.Client) gin.HandlerFunc {
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

		output, err := dockerClient.ExecCommand("crowdsec", []string{
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

// CheckTraefikIntegration checks Traefik-CrowdSec integration
func CheckTraefikIntegration(dockerClient *docker.Client, db *database.Database) gin.HandlerFunc {
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
			output, err := dockerClient.ExecCommand("traefik", []string{"cat", path})
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

		// Check if captcha.html exists
		_, htmlErr := dockerClient.ExecCommand("traefik", []string{
			"test", "-f", "/etc/traefik/captcha.html",
		})
		if htmlErr == nil {
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
func GetDecisionsAnalysis(dockerClient *docker.Client) gin.HandlerFunc {
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

		output, err := dockerClient.ExecCommand("crowdsec", cmd)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to get decisions: %v", err),
			})
			return
		}

		// Parse the JSON to ensure it's valid and return as structured data
		var decisions []models.Decision
		if err := json.Unmarshal([]byte(output), &decisions); err != nil {
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

		logger.Debug("Decisions analysis retrieved successfully", "count", len(decisions))

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"decisions": decisions, "count": len(decisions)},
		})
	}
}

// GetAlertsAnalysis retrieves CrowdSec alerts with advanced filtering
func GetAlertsAnalysis(dockerClient *docker.Client) gin.HandlerFunc {
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

		output, err := dockerClient.ExecCommand("crowdsec", cmd)
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
// HELPER FUNCTIONS
// =============================================================================

// truncateString truncates a string to a maximum length for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "... (truncated)"
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
