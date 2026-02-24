package handlers

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/constants"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// parseWhitelistYAML parses whitelist YAML content and extracts IPs (IPv4 and IPv6)
func parseWhitelistYAML(content string) []string {
	ips := []string{}
	lines := strings.Split(content, "\n")

	// Match IPv4 (with optional CIDR) and IPv6 (with optional CIDR)
	ipRegex := regexp.MustCompile(`^\s*-\s+([0-9a-fA-F.:\/]+)`)
	for _, line := range lines {
		if matches := ipRegex.FindStringSubmatch(line); len(matches) > 1 {
			ips = append(ips, matches[1])
		}
	}

	return ips
}

// parseTraefikWhitelist parses Traefik whitelist configuration (IPv4 and IPv6)
func parseTraefikWhitelist(content string) []string {
	ips := []string{}
	lines := strings.Split(content, "\n")

	// Match IPv4 (with optional CIDR) and IPv6 (with optional CIDR)
	ipRegex := regexp.MustCompile(`^\s*-\s+([0-9a-fA-F.:\/]+)`)
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

// AddToCrowdSecWhitelist adds an IP to CrowdSec whitelist only
func AddToCrowdSecWhitelist(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
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

		if err := dockerClient.WriteFileToContainer(cfg.CrowdsecContainerName, cfg.CrowdSecWhitelistPath, []byte(whitelistContent)); err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update whitelist: %v", err),
			})
			return
		}

		_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "parsers", "reload"})

		autoSnapshot("whitelist")

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("IP %s added to CrowdSec whitelist", req.IP),
		})
	}
}

// AddToTraefikWhitelist adds an IP to Traefik whitelist only
func AddToTraefikWhitelist(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		var req models.WhitelistRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Adding to Traefik whitelist", "ip", req.IP)

		err := dockerClient.AppendLineToFileInContainer(cfg.TraefikContainerName, cfg.TraefikDynamicConfig, "sourceRange:", "        - "+req.IP)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to update whitelist: %v", err),
			})
			return
		}

		autoSnapshot("dynamic_config")

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("IP %s added to Traefik whitelist", req.IP),
		})
	}
}

// RemoveFromWhitelist removes an IP from CrowdSec and/or Traefik whitelists
func RemoveFromWhitelist(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		var req models.WhitelistDeleteRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Removing IP from whitelist", "ip", req.IP)

		var errors []string
		var successMessages []string

		if req.RemoveFromCrowdSec {
			// Read current whitelist, remove the IP, write back
			currentWL, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
				"cat", cfg.CrowdSecWhitelistPath,
			})
			if err != nil {
				errors = append(errors, fmt.Sprintf("Failed to read CrowdSec whitelist: %v", err))
			} else {
				lines := strings.Split(currentWL, "\n")
				var newLines []string
				ipPattern := regexp.MustCompile(`^\s*-\s+` + regexp.QuoteMeta(req.IP) + `\s*$`)
				for _, line := range lines {
					if !ipPattern.MatchString(line) {
						newLines = append(newLines, line)
					}
				}
				newContent := strings.Join(newLines, "\n")
				if err := dockerClient.WriteFileToContainer(cfg.CrowdsecContainerName, cfg.CrowdSecWhitelistPath, []byte(newContent)); err != nil {
					errors = append(errors, fmt.Sprintf("Failed to update CrowdSec whitelist: %v", err))
				} else {
					_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "parsers", "reload"})
					successMessages = append(successMessages, "Removed from CrowdSec whitelist")
				}
			}
		}

		if req.RemoveFromTraefik {
			// Read current Traefik config, remove the IP, write back
			currentConfig, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
				"cat", cfg.TraefikDynamicConfig,
			})
			if err != nil {
				errors = append(errors, fmt.Sprintf("Failed to read Traefik config: %v", err))
			} else {
				lines := strings.Split(currentConfig, "\n")
				var newLines []string
				ipPattern := regexp.MustCompile(`^\s*-\s+` + regexp.QuoteMeta(req.IP) + `\s*$`)
				for _, line := range lines {
					if !ipPattern.MatchString(line) {
						newLines = append(newLines, line)
					}
				}
				newContent := strings.Join(newLines, "\n")
				if err := dockerClient.WriteFileToContainer(cfg.TraefikContainerName, cfg.TraefikDynamicConfig, []byte(newContent)); err != nil {
					errors = append(errors, fmt.Sprintf("Failed to update Traefik config: %v", err))
				} else {
					successMessages = append(successMessages, "Removed from Traefik whitelist")
				}
			}
		}

		if len(errors) > 0 && len(successMessages) == 0 {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   strings.Join(errors, "; "),
			})
			return
		}

		autoSnapshot("whitelist")

		message := fmt.Sprintf("IP %s removed: %s", req.IP, strings.Join(successMessages, ", "))
		if len(errors) > 0 {
			message += fmt.Sprintf(" (errors: %s)", strings.Join(errors, "; "))
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: message,
		})
	}
}

// SetupComprehensiveWhitelist sets up complete whitelist configuration
func SetupComprehensiveWhitelist(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
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
			resp, err := constants.ExternalHTTPClient.Get(constants.ExternalIPServices[0])
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

		if err := dockerClient.WriteFileToContainer(cfg.CrowdsecContainerName, cfg.CrowdSecWhitelistPath, []byte(whitelistContent)); err == nil {
			_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "parsers", "reload"})
			results["crowdsec"] = true
		}

		// Add to Traefik
		if err := dockerClient.AppendLineToFileInContainer(cfg.TraefikContainerName, cfg.TraefikDynamicConfig, "sourceRange:", "        - "+ip); err == nil {
			results["traefik"] = true
		}

		autoSnapshot("whitelist")
		autoSnapshot("dynamic_config")

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Comprehensive whitelist setup completed",
			Data:    results,
		})
	}
}
