package handlers

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/traefikconfig"

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

		publicIP, err := getExternalIP()
		if err != nil {
			logger.Error("Failed to get public IP", "error", err)
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
		dockerClient = resolveDockerClient(c, dockerClient)
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
		dataBytes, parseErr := parseCLIJSONToBytes(output)
		if parseErr != nil || json.Unmarshal(dataBytes, &decisions) != nil {
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

			if parseErr != nil {
				logger.Error("Failed to normalize decisions JSON", "error", parseErr, "output", output)
			} else {
				logger.Error("Failed to parse decisions JSON", "output", output)
			}
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to parse response",
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
		dockerClient = resolveDockerClient(c, dockerClient)
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
			if dataBytes, parseErr := parseCLIJSONToBytes(decisionsOutput); parseErr == nil {
				if json.Unmarshal(dataBytes, &decisions) == nil {
					result.IsBlocked = len(decisions) > 0
				}
			}
		}

		// 2. Check CrowdSec allowlists
		allowlistOutput, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cscli", "allowlists", "list", "-o", "json",
		})
		if err == nil && allowlistOutput != "null" && allowlistOutput != "" && allowlistOutput != "[]" {
			// Parse allowlists and check if IP is in any of them
			dataBytes, parseErr := parseCLIJSONToBytes(allowlistOutput)
			if parseErr != nil {
				logger.Warn("Failed to normalize allowlists JSON", "error", parseErr)
			}
			if parseErr != nil {
				dataBytes = []byte(allowlistOutput)
			}
			inAllowlist := false

			_, arrErr := jsonparser.ArrayEach(dataBytes, func(allowlistValue []byte, dataType jsonparser.ValueType, offset int, err error) {
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

			if arrErr != nil {
				logger.Warn("Failed to parse allowlists", "error", arrErr)
			}
		}

		// 3. Check CrowdSec parsers whitelist
		// Find all files containing "whitelist" in the whitelist directory
		whitelistDir := filepath.Dir(cfg.CrowdSecWhitelistPath)
		findWhitelistFiles, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"find", whitelistDir, "-type", "f", "(", "-name", "*whitelist*.yaml", "-o", "-name", "*whitelist*.yml", ")",
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

		// 4. Check the configured Traefik dynamic config path for ipAllowList/sourceRange.
		dynamicConfigPaths := append([]string{cfg.TraefikDynamicConfig}, cfg.TraefikDynamicConfigSearch...)

		for _, configPath := range dynamicConfigPaths {
			readResult, err := traefikconfig.ReadContainer(dockerClient, cfg.TraefikContainerName, configPath)
			traefikData := readResult.Content
			if err == nil && traefikData != "" {
				if (strings.Contains(traefikData, "ipWhiteList") || strings.Contains(traefikData, "ipAllowList") || strings.Contains(traefikData, "sourceRange")) &&
					(strings.Contains(traefikData, ip) || checkIPInCIDRList(ip, traefikData)) {
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
		dockerClient = resolveDockerClient(c, dockerClient)
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
