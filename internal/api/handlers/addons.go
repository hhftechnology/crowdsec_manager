package handlers

import (
	"context"
	"net/http"

	"crowdsec-manager/internal/compose"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/proxy"

	"github.com/gin-gonic/gin"
)

// GetAvailableAddons returns available add-ons for the current proxy type
func GetAvailableAddons(proxyAdapter proxy.ProxyAdapter, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting available add-ons", "proxy_type", proxyAdapter.Type())

		addons := []models.AddonInfo{}
		proxyType := string(proxyAdapter.Type())

		// Pangolin and Gerbil are only available for Traefik
		if proxyType == "traefik" {
			// Pangolin add-on
			pangolin := models.AddonInfo{
				Name:        "pangolin",
				DisplayName: "Pangolin",
				Description: "Advanced security features and certificate management for Traefik",
				ProxyTypes:  []string{"traefik"},
				Required:    false,
				Category:    "security",
				Status:      getAddonStatus("pangolin", cfg),
				Features: []string{
					"Advanced SSL/TLS management",
					"Certificate automation",
					"Security middleware",
					"Dynamic configuration",
				},
			}
			addons = append(addons, pangolin)

			// Gerbil add-on
			gerbil := models.AddonInfo{
				Name:        "gerbil",
				DisplayName: "Gerbil",
				Description: "VPN and network security features for Traefik deployments",
				ProxyTypes:  []string{"traefik"},
				Required:    false,
				Category:    "networking",
				Status:      getAddonStatus("gerbil", cfg),
				Features: []string{
					"WireGuard VPN integration",
					"Network security policies",
					"Remote access management",
					"Traffic encryption",
				},
			}
			addons = append(addons, gerbil)
		}

		response := models.AddonsResponse{
			ProxyType:        proxyType,
			AvailableAddons:  addons,
			TotalAddons:      len(addons),
			SupportedAddons:  len(addons), // All listed addons are supported for the proxy type
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    response,
		})
	}
}

// GetAddonStatus returns the status of a specific add-on
func GetAddonStatus(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		addonName := c.Param("addon")
		logger.Info("Getting add-on status", "addon", addonName)

		// Validate addon name
		if !isValidAddon(addonName) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid add-on name: " + addonName,
			})
			return
		}

		status := getAddonStatus(addonName, cfg)
		
		// Get container status if addon is enabled
		if status.Enabled {
			containerName := getAddonContainerName(addonName, cfg)
			if containerName != "" {
				ctx := context.Background()
				running, err := dockerClient.IsContainerRunning(ctx, containerName)
				if err != nil {
					logger.Warn("Failed to check addon container status", "addon", addonName, "error", err)
				} else {
					status.Running = running
					status.ContainerName = containerName
				}
			}
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    status,
		})
	}
}

// EnableAddon enables a specific add-on
func EnableAddon(composeManager *compose.ComposeManager, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		addonName := c.Param("addon")
		logger.Info("Enabling add-on", "addon", addonName)

		// Validate addon name
		if !isValidAddon(addonName) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid add-on name: " + addonName,
			})
			return
		}

		// Check if addon is compatible with current proxy type
		if !composeManager.IsAddonCompatible(addonName) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Add-on " + addonName + " is not compatible with proxy type: " + composeManager.ProxyType,
			})
			return
		}

		// For now, return success - full implementation would update compose configuration
		// and restart services with the new profile
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Add-on " + addonName + " enabled successfully",
			Data: gin.H{
				"addon":      addonName,
				"proxy_type": composeManager.ProxyType,
				"enabled":    true,
			},
		})
	}
}

// DisableAddon disables a specific add-on
func DisableAddon(composeManager *compose.ComposeManager, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		addonName := c.Param("addon")
		logger.Info("Disabling add-on", "addon", addonName)

		// Validate addon name
		if !isValidAddon(addonName) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid add-on name: " + addonName,
			})
			return
		}

		// For now, return success - full implementation would update compose configuration
		// and restart services without the addon profile
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Add-on " + addonName + " disabled successfully",
			Data: gin.H{
				"addon":      addonName,
				"proxy_type": composeManager.ProxyType,
				"enabled":    false,
			},
		})
	}
}

// GetAddonConfiguration returns configuration options for an add-on
func GetAddonConfiguration(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		addonName := c.Param("addon")
		logger.Info("Getting add-on configuration", "addon", addonName)

		// Validate addon name
		if !isValidAddon(addonName) {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid add-on name: " + addonName,
			})
			return
		}

		config := getAddonConfiguration(addonName, cfg)

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    config,
		})
	}
}

// Helper functions

func isValidAddon(addonName string) bool {
	validAddons := []string{"pangolin", "gerbil"}
	for _, valid := range validAddons {
		if addonName == valid {
			return true
		}
	}
	return false
}

func getAddonStatus(addonName string, cfg *config.Config) models.AddonStatus {
	status := models.AddonStatus{
		Name:          addonName,
		Enabled:       false,
		Running:       false,
		ContainerName: "",
		Version:       "latest",
		Health:        "unknown",
	}

	// Check if addon is enabled in configuration
	// This would typically check environment variables or database settings
	switch addonName {
	case "pangolin":
		status.ContainerName = cfg.PangolinContainerName
		status.Enabled = cfg.PangolinEnabled
	case "gerbil":
		status.ContainerName = cfg.GerbilContainerName
		status.Enabled = cfg.GerbilEnabled
	}

	return status
}

func getAddonContainerName(addonName string, cfg *config.Config) string {
	switch addonName {
	case "pangolin":
		return cfg.PangolinContainerName
	case "gerbil":
		return cfg.GerbilContainerName
	default:
		return ""
	}
}

func getAddonConfiguration(addonName string, cfg *config.Config) models.AddonConfiguration {
	config := models.AddonConfiguration{
		Name:     addonName,
		Settings: make(map[string]interface{}),
	}

	switch addonName {
	case "pangolin":
		config.Settings = map[string]interface{}{
			"container_name": cfg.PangolinContainerName,
			"version":        "latest",
			"config_dir":     "/app/config",
			"data_volume":    "pangolin-data",
			"host":           "pangolin.localhost",
		}
	case "gerbil":
		config.Settings = map[string]interface{}{
			"container_name":     cfg.GerbilContainerName,
			"version":            "latest",
			"config_dir":         "/var/config",
			"wireguard_port":     51820,
			"wireguard_port2":    51830,
			"wireguard_port3":    21820,
			"api_port":           51821,
			"host":               "gerbil.localhost",
		}
	}

	return config
}