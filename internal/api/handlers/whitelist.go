package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// appendToYAMLList appends a new list item under a YAML section key, using the
// same indentation as existing list items in that block. Falls back to 4-space
// indent if the block has no existing items.
func appendToYAMLList(content, sectionKey, value string) string {
	lines := strings.Split(strings.TrimSpace(content), "\n")
	detectedIndent := "    " // default 4 spaces
	sectionIndent := -1
	for _, line := range lines {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, sectionKey) {
			sectionIndent = len(line) - len(trimmed)
			continue
		}
		if sectionIndent < 0 {
			continue
		}
		if trimmed == "" {
			continue
		}
		lineIndent := len(line) - len(trimmed)
		if lineIndent <= sectionIndent {
			break
		}
		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			detectedIndent = line[:lineIndent]
		}
	}
	return strings.TrimSpace(content) + "\n" + detectedIndent + "- " + value + "\n"
}

// =============================================================================
// 3. WHITELIST MANAGEMENT
// =============================================================================

// ViewWhitelist displays all whitelisted IPs from both CrowdSec and Traefik
func ViewWhitelist(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		dockerClient = resolveDockerClient(c, dockerClient)
		logger.Info("Viewing whitelist")

		whitelist := gin.H{
			"crowdsec": []string{},
			"traefik":  []string{},
		}

		// Get CrowdSec whitelist
		crowdsecWL, err := dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{
			"cat", cfg.CrowdSecWhitelistPath,
		})
		if err == nil {
			whitelist["crowdsec"] = parseWhitelistYAML(crowdsecWL)
		}

		// Get Traefik whitelist
		traefikWL, err := dockerClient.ExecCommand(cfg.TraefikContainerName, []string{
			"cat", cfg.TraefikDynamicConfig,
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
		dockerClient = resolveDockerClient(c, dockerClient)
		logger.Info("Whitelisting current IP")

		publicIP, err := getExternalIP()
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to get public IP: " + err.Error(),
			})
			return
		}

		// Add to CrowdSec whitelist
		whitelistContent := fmt.Sprintf(`name: mywhitelists
description: "My custom whitelists"
whitelist:
  reason: "Admin IP"
  ip:
    - %s
`, publicIP)

		// Write to CrowdSec container
		err = dockerClient.WriteFileToContainer(cfg.CrowdsecContainerName, cfg.CrowdSecWhitelistPath, []byte(whitelistContent))
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
		dockerClient = resolveDockerClient(c, dockerClient)
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
				"cat", cfg.CrowdSecWhitelistPath,
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
				// Append to existing whitelist, matching its existing indentation
				whitelistContent = appendToYAMLList(currentWL, "ip:", req.IP)
			}

			err = dockerClient.WriteFileToContainer(cfg.CrowdsecContainerName, cfg.CrowdSecWhitelistPath, []byte(whitelistContent))
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
			err := dockerClient.AppendLineToFileInContainer(cfg.TraefikContainerName, cfg.TraefikDynamicConfig, "sourceRange:", "- "+req.IP)
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
		dockerClient = resolveDockerClient(c, dockerClient)
		var req models.WhitelistRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Whitelisting CIDR", "cidr", req.CIDR)

		var errors []string

		if req.AddToCrowdSec {
			whitelistContent := fmt.Sprintf(`name: mywhitelists
description: "My custom whitelists"
whitelist:
  reason: "CIDR range"
  ip:
    - %s
`, req.CIDR)

			err := dockerClient.WriteFileToContainer(cfg.CrowdsecContainerName, cfg.CrowdSecWhitelistPath, []byte(whitelistContent))
			if err != nil {
				errMsg := fmt.Sprintf("Failed to update CrowdSec whitelist: %v", err)
				logger.Error(errMsg, "error", err)
				errors = append(errors, errMsg)
			} else {
				_, _ = dockerClient.ExecCommand(cfg.CrowdsecContainerName, []string{"cscli", "parsers", "reload"})
			}
		}

		if req.AddToTraefik {
			err := dockerClient.AppendLineToFileInContainer(cfg.TraefikContainerName, cfg.TraefikDynamicConfig, "sourceRange:", "- "+req.CIDR)
			if err != nil {
				errMsg := fmt.Sprintf("Failed to add CIDR to Traefik whitelist: %v", err)
				logger.Error(errMsg, "error", err)
				errors = append(errors, errMsg)
			}
		}

		if len(errors) > 0 {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   fmt.Sprintf("Failed to whitelist CIDR %s: %s", req.CIDR, strings.Join(errors, "; ")),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: fmt.Sprintf("CIDR %s has been whitelisted", req.CIDR),
		})
	}
}
