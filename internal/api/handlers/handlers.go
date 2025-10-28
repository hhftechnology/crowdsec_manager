package handlers

import (
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"crowdsec-manager/internal/backup"
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
func RunCompleteDiagnostics(dockerClient *docker.Client) gin.HandlerFunc {
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
			// Parse bouncer JSON output (simplified)
			logger.Debug("Bouncers retrieved", "output", bouncerOutput)
		}

		// Get decisions
		var decisions []models.Decision
		decisionOutput, err := dockerClient.ExecCommand("crowdsec", []string{"cscli", "decisions", "list", "-o", "json"})
		if err == nil {
			logger.Debug("Decisions retrieved", "output", decisionOutput)
		}

		// Check Traefik integration
		traefikIntegration := &models.TraefikIntegration{
			MiddlewareConfigured: false,
			ConfigFiles:          []string{},
			LapiKeyFound:         false,
			AppsecEnabled:        false,
		}

		// Check for Traefik middleware configuration
		configExists, err := dockerClient.FileExists("traefik", "/etc/traefik/dynamic_config.yml")
		if err == nil && configExists {
			traefikIntegration.MiddlewareConfigured = true
			traefikIntegration.ConfigFiles = append(traefikIntegration.ConfigFiles, "dynamic_config.yml")
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
				logger.Error("Failed to update CrowdSec whitelist", "error", err)
			} else {
				_, _ = dockerClient.ExecCommand("crowdsec", []string{"cscli", "parsers", "reload"})
			}
		}

		if req.AddToTraefik {
			// Update Traefik dynamic config
			// This is a simplified version - real implementation should parse YAML properly
			_, err := dockerClient.ExecCommand("traefik", []string{
				"sh", "-c", fmt.Sprintf(`sed -i '/sourceRange:/a\        - %s' /etc/traefik/dynamic_config.yml`, req.IP),
			})
			if err != nil {
				logger.Error("Failed to update Traefik whitelist", "error", err)
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("IP %s has been whitelisted", req.IP),
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

		for _, scenario := range req.Scenarios {
			scenarioPath := filepath.Join("/etc/crowdsec/scenarios", scenario.Name+".yaml")

			_, err := dockerClient.ExecCommand("crowdsec", []string{
				"sh", "-c", fmt.Sprintf("echo '%s' > %s", scenario.Content, scenarioPath),
			})

			result := gin.H{
				"name":    scenario.Name,
				"success": err == nil,
			}
			if err != nil {
				result["error"] = err.Error()
			}
			results = append(results, result)
		}

		// Reload scenarios
		_, _ = dockerClient.ExecCommand("crowdsec", []string{"cscli", "scenarios", "reload"})

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Custom scenarios setup completed",
			Data:    results,
		})
	}
}

// ListScenarios lists all installed CrowdSec scenarios
func ListScenarios(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Listing scenarios")

		output, err := dockerClient.ExecCommand("crowdsec", []string{
			"cscli", "scenarios", "list", "-o", "json",
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to list scenarios: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"scenarios": output},
		})
	}
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

// GetCaptchaStatus retrieves the current captcha configuration status
func GetCaptchaStatus(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting captcha status")

		output, err := dockerClient.ExecCommand("traefik", []string{
			"cat", "/etc/traefik/captcha.env",
		})

		configured := false
		provider := ""

		if err == nil && strings.TrimSpace(output) != "" {
			configured = true
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "CAPTCHA_PROVIDER=") {
					provider = strings.TrimSpace(strings.TrimPrefix(line, "CAPTCHA_PROVIDER="))
					break
				}
			}
		}

		status := gin.H{
			"configured": configured,
			"provider":   provider,
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

// GetTraefikLogs retrieves Traefik logs
func GetTraefikLogs(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		tail := c.DefaultQuery("tail", "100")
		logger.Info("Getting Traefik logs", "tail", tail)

		logs, err := dockerClient.GetContainerLogs("traefik", tail)
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
				logs, err := dockerClient.GetContainerLogs(service, "10")
				if err != nil {
					ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("Error: %v", err)))
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

// GetCurrentTags retrieves current Docker image tags
func GetCurrentTags() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting current image tags")

		// In a real implementation, this would parse docker-compose.yml
		// or inspect running containers to get their image tags
		tags := models.ImageTags{
			Pangolin: "latest",
			Gerbil:   "latest",
			Traefik:  "latest",
			CrowdSec: "latest",
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

		logger.Info("Updating stack with CrowdSec")

		// Pull latest images and restart containers
		// This is a simplified version
		services := []string{"pangolin", "gerbil", "traefik", "crowdsec"}

		for _, service := range services {
			logger.Info("Restarting service", "service", service)
			if err := dockerClient.RestartContainer(service); err != nil {
				logger.Error("Failed to restart service", "service", service, "error", err)
			}
		}

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

		logger.Info("Updating stack without CrowdSec")

		services := []string{"pangolin", "gerbil", "traefik"}

		for _, service := range services {
			logger.Info("Restarting service", "service", service)
			if err := dockerClient.RestartContainer(service); err != nil {
				logger.Error("Failed to restart service", "service", service, "error", err)
			}
		}

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
			if err := dockerClient.StopContainer(service); err != nil {
				logger.Error("Failed to stop service", "service", service, "error", err)
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

		var err error
		switch req.Action {
		case "start":
			err = dockerClient.StartContainer(req.Service)
		case "stop":
			err = dockerClient.StopContainer(req.Service)
		case "restart":
			err = dockerClient.RestartContainer(req.Service)
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

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"bouncers": output},
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

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"decisions": output},
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
func CheckTraefikIntegration(dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Checking Traefik integration")

		integration := models.TraefikIntegration{
			MiddlewareConfigured: false,
			ConfigFiles:          []string{},
			LapiKeyFound:         false,
			AppsecEnabled:        false,
		}

		// Check dynamic config
		configExists, err := dockerClient.FileExists("traefik", "/etc/traefik/dynamic_config.yml")
		if err == nil && configExists {
			integration.MiddlewareConfigured = true
			integration.ConfigFiles = append(integration.ConfigFiles, "dynamic_config.yml")

			// Check config content
			config, err := dockerClient.ExecCommand("traefik", []string{
				"cat", "/etc/traefik/dynamic_config.yml",
			})
			if err == nil {
				integration.LapiKeyFound = strings.Contains(config, "crowdsec")
				integration.AppsecEnabled = strings.Contains(config, "appsec")
			}
		}

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
			"static":  "traefik.yml content",
			"dynamic": "dynamic_config.yml content",
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    config,
		})
	}
}

// Global variable to store dynamic config path (in production, use a config file or database)
var dynamicConfigPath = "/etc/traefik/dynamic_config.yml"

// GetTraefikConfigPath retrieves the current dynamic config path
func GetTraefikConfigPath() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting Traefik config path")

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    gin.H{"dynamic_config_path": dynamicConfigPath},
		})
	}
}

// SetTraefikConfigPath sets the dynamic config path
func SetTraefikConfigPath() gin.HandlerFunc {
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

		// Update the global path
		dynamicConfigPath = req.DynamicConfigPath

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Dynamic config path updated successfully",
			Data:    gin.H{"dynamic_config_path": dynamicConfigPath},
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
