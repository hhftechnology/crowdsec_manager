package handlers

import (
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/crowdsec"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

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
func IsIPBlocked(dockerClient *docker.Client, cfg *config.Config, csClient *crowdsec.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.Param("ip")
		if ip == "" {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "IP address is required",
			})
			return
		}

		logger.Info("Checking if IP is blocked via LAPI", "ip", ip)

		decisions, err := csClient.GetDecisions(url.Values{"ip": []string{ip}})
		if err != nil {
			logger.Error("Failed to check IP block status", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to check IP status: %v", err),
			})
			return
		}

		blocked := len(decisions) > 0
		var reason string
		if blocked {
			reason = decisions[0].Scenario
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

// UnbanIP unbans an IP address
func UnbanIP(dockerClient *docker.Client, cfg *config.Config, csClient *crowdsec.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.UnbanRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Unbanning IP via LAPI", "ip", req.IP)

		err := csClient.DeleteDecision(req.IP, "")
		if err != nil {
			logger.Error("Failed to unban IP", "error", err)
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to unban IP: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("IP %s unbanned successfully", req.IP),
		})
	}
}
