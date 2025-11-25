package handlers

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

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
