package handlers

import (
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/buger/jsonparser"
	"github.com/gin-gonic/gin"
)

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


// IsIPBlocked checks if an IP is blocked
func IsIPBlocked(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.Param("ip")
		if ip == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "IP address is required",
			})
			return
		}

		logger.Info("Checking if IP is blocked via cscli", "ip", ip)

		// Use cscli decisions list with JSON output
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "decisions", "list", "--ip", ip, "-o", "json",
		})
		if err != nil {
			logger.Error("Failed to check IP block status", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to check IP status: %v", err),
			})
			return
		}

		// Parse the JSON output
		var decisions []models.DecisionRaw
		if err := json.Unmarshal([]byte(output), &decisions); err != nil {
			// If output is empty or "null", it means no decisions (not blocked)
			if output == "null" || output == "" {
				c.JSON(http.StatusOK, models.Response{
					Success: true,
					Data: gin.H{
						"ip":      ip,
						"blocked": false,
						"reason":  "",
					},
				})
				return
			}

			logger.Error("Failed to parse decisions JSON", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to parse response: %v", err),
			})
			return
		}

		blocked := len(decisions) > 0
		var reason string
		if blocked {
			// Use the first decision's scenario/reason
			reason = decisions[0].Scenario
			if reason == "" {
				reason = decisions[0].Reason
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: gin.H{
				"ip":      ip,
				"blocked": blocked,
				"reason":  reason,
			},
		})
	}
}

// CheckIPSecurity provides comprehensive security information about an IP
func CheckIPSecurity(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.Param("ip")
		if ip == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "IP address is required",
			})
			return
		}

		logger.Info("Performing comprehensive security check", "ip", ip)

		result := models.IPInfo{
			IP:            ip,
			IsBlocked:     false,
			IsWhitelisted: false,
			InCrowdSec:    false,
			InTraefik:     false,
		}

		// 1. Check if IP is blocked in CrowdSec decisions
		decisionsOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "decisions", "list", "--ip", ip, "-o", "json",
		})
		if err == nil && decisionsOutput != "null" && decisionsOutput != "" && decisionsOutput != "[]" {
			var decisions []interface{}
			if json.Unmarshal([]byte(decisionsOutput), &decisions) == nil {
				result.IsBlocked = len(decisions) > 0
			}
		}

		// 2. Check CrowdSec allowlists
		allowlistOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "allowlists", "list", "-o", "json",
		})
		if err == nil && allowlistOutput != "null" && allowlistOutput != "" && allowlistOutput != "[]" {
			// Parse allowlists and check if IP is in any of them
			dataBytes := []byte(allowlistOutput)
			inAllowlist := false

			_, parseErr := jsonparser.ArrayEach(dataBytes, func(allowlistValue []byte, dataType jsonparser.ValueType, offset int, err error) {
				if inAllowlist {
					return // Already found
				}

				// Check items in this allowlist
				jsonparser.ArrayEach(allowlistValue, func(itemValue []byte, itemType jsonparser.ValueType, itemOffset int, itemErr error) {
					if value, err := jsonparser.GetString(itemValue, "value"); err == nil {
						// Check if IP matches the allowlist entry (exact match or CIDR)
						if value == ip {
							// Exact IP match
							inAllowlist = true
							result.InCrowdSec = true
							result.IsWhitelisted = true
						} else if strings.Contains(value, "/") {
							// CIDR range - use proper CIDR matching
							targetIP := net.ParseIP(ip)
							if targetIP != nil {
								_, ipNet, err := net.ParseCIDR(value)
								if err == nil && ipNet.Contains(targetIP) {
									inAllowlist = true
									result.InCrowdSec = true
									result.IsWhitelisted = true
								}
							}
						}
					}
				}, "items")
			})

			if parseErr != nil {
				logger.Warn("Failed to parse allowlists", "error", parseErr)
			}
		}

		// 3. Check CrowdSec parsers whitelist
		// Find all files containing "whitelist" in /etc/crowdsec/parsers/s02-enrich/
		findWhitelistFiles, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"sh", "-c", "find /etc/crowdsec/parsers/s02-enrich/ -type f -name '*whitelist*.yaml' -o -name '*whitelist*.yml' 2>/dev/null || echo ''",
		})
		if err == nil && findWhitelistFiles != "" {
			whitelistFiles := strings.Split(strings.TrimSpace(findWhitelistFiles), "\n")
			for _, whitelistFile := range whitelistFiles {
				if whitelistFile == "" {
					continue
				}
				// Read and check each whitelist file for the IP
				whitelistContent, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
					"cat", whitelistFile,
				})
				if err == nil && strings.Contains(whitelistContent, ip) {
					result.IsWhitelisted = true
					result.InCrowdSec = true
					break
				}
			}
		}

		// 4. Check Traefik dynamic_config.yml for ipWhiteList
		// Read Traefik dynamic configuration
		dynamicConfigPaths := []string{
			"/etc/traefik/dynamic_config.yml",
			"/etc/traefik/config/dynamic_config.yml",
			"/etc/traefik/dynamic_config.yaml",
			"/etc/traefik/config/dynamic_config.yaml",
		}

		for _, configPath := range dynamicConfigPaths {
			traefikData, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
				"cat", configPath,
			})
			if err == nil && traefikData != "" {
				// Check if IP is in the sourceRange list
				// Parse YAML to check ipWhiteList.sourceRange
				if strings.Contains(traefikData, "ipWhiteList") && (strings.Contains(traefikData, ip) || checkIPInCIDRList(ip, traefikData)) {
					result.InTraefik = true
					result.IsWhitelisted = true
					break
				}
			}
		}

		logger.Info("Security check completed",
			"ip", ip,
			"blocked", result.IsBlocked,
			"whitelisted", result.IsWhitelisted,
			"in_crowdsec", result.InCrowdSec,
			"in_traefik", result.InTraefik)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    result,
		})
	}
}

// UnbanIP unbans an IP address
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

		logger.Info("Unbanning IP via cscli", "ip", req.IP)

		// Use cscli decisions delete
		output, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "decisions", "delete", "--ip", req.IP,
		})
		if err != nil {
			logger.Error("Failed to unban IP", "error", err, "output", output)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to unban IP: %v", err),
			})
			return
		}

		// Check output for success/failure if needed, but usually exit code is enough
		// cscli outputs "No decision(s) deleted" if nothing found, which is fine

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("IP %s unbanned successfully", req.IP),
			Data:    gin.H{"output": output},
		})
	}
}

// Helper function to check if an IP is in any CIDR range from the YAML content
func checkIPInCIDRList(ip, yamlContent string) bool {
	// Parse the target IP
	targetIP := net.ParseIP(ip)
	if targetIP == nil {
		return false
	}

	// Extract CIDR ranges from sourceRange list in YAML
	// Look for patterns like "- 10.0.0.0/8"
	lines := strings.Split(yamlContent, "\n")
	inSourceRange := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Check if we're in a sourceRange section
		if strings.Contains(trimmed, "sourceRange:") {
			inSourceRange = true
			continue
		}

		// If we're in sourceRange and find a list item
		if inSourceRange && strings.HasPrefix(trimmed, "- ") {
			cidr := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			// Remove quotes if present
			cidr = strings.Trim(cidr, "\"'")

			// Check if it's a CIDR range (contains /)
			if strings.Contains(cidr, "/") {
				// Use net.ParseCIDR for proper CIDR matching
				_, ipNet, err := net.ParseCIDR(cidr)
				if err == nil && ipNet.Contains(targetIP) {
					return true
				}
			} else {
				// Exact IP match (no CIDR notation)
				if cidr == ip {
					return true
				}
			}
		} else if inSourceRange && !strings.HasPrefix(trimmed, "- ") && trimmed != "" {
			// Exit sourceRange section if we hit something else
			inSourceRange = false
		}
	}

	return false
}
