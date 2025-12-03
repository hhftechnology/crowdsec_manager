package handlers

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

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
  reason: "Comprehensive setup"
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
