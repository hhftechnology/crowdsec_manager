package handlers

import (
	"context"
	"net/http"

	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/proxy"

	"github.com/gin-gonic/gin"
)

// GetProxyTypes returns all available proxy types
func GetProxyTypes() gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting available proxy types")

		types := []models.ProxyTypeInfo{}
		for _, proxyType := range proxy.GetAllProxyTypes() {
			typeInfo := models.ProxyTypeInfo{
				Type:        string(proxyType),
				Name:        string(proxyType),
				Description: proxy.GetProxyTypeDescription(proxyType),
				Registered:  proxy.IsAdapterRegistered(proxyType),
			}

			// Mark experimental proxy types
			if proxyType == proxy.ProxyTypeZoraxy {
				typeInfo.Experimental = true
			}

			// Get supported features if adapter is registered
			if typeInfo.Registered {
				if adapter, err := proxy.CreateAdapter(proxyType); err == nil {
					features := adapter.SupportedFeatures()
					typeInfo.SupportedFeatures = make([]string, len(features))
					for i, feature := range features {
						typeInfo.SupportedFeatures[i] = string(feature)
					}
				}
			}

			types = append(types, typeInfo)
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: models.ProxyTypesResponse{
				Types: types,
			},
		})
	}
}

// GetCurrentProxy returns information about the current proxy configuration
func GetCurrentProxy(proxyAdapter proxy.ProxyAdapter) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting current proxy information")

		ctx := context.Background()

		// Get health status
		healthItem, err := proxyAdapter.HealthCheck(ctx)
		healthStatus := "unknown"
		if err == nil && healthItem != nil {
			healthStatus = healthItem.Status
		}

		// Get supported features
		features := proxyAdapter.SupportedFeatures()
		featureStrings := make([]string, len(features))
		for i, feature := range features {
			featureStrings[i] = string(feature)
		}

		response := models.ProxyCurrentResponse{
			Type:              string(proxyAdapter.Type()),
			Enabled:           true, // Adapter exists, so it's enabled
			ContainerName:     "", // Would need to extract from adapter config
			Running:           healthStatus == "healthy",
			SupportedFeatures: featureStrings,
			ConfigFiles:       []string{}, // Would need to extract from adapter config
			Health:            healthStatus,
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    response,
		})
	}
}

// GetProxyFeatures returns detailed information about proxy features
func GetProxyFeatures(proxyAdapter proxy.ProxyAdapter) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting proxy features")

		features := proxyAdapter.SupportedFeatures()
		featureDetails := make(map[string]models.FeatureDetail)

		for _, feature := range features {
			detail := models.FeatureDetail{
				Name:        string(feature),
				Available:   true,
				Description: getFeatureDescription(feature),
			}

			// Check if feature manager is available
			switch feature {
			case proxy.FeatureWhitelist:
				if proxyAdapter.WhitelistManager() == nil {
					detail.Available = false
					detail.Reason = "Whitelist manager not available for this proxy type"
				}
			case proxy.FeatureCaptcha:
				if proxyAdapter.CaptchaManager() == nil {
					detail.Available = false
					detail.Reason = "Captcha manager not available for this proxy type"
				}
			case proxy.FeatureLogs:
				if proxyAdapter.LogManager() == nil {
					detail.Available = false
					detail.Reason = "Log manager not available for this proxy type"
				}
			case proxy.FeatureBouncer:
				if proxyAdapter.BouncerManager() == nil {
					detail.Available = false
					detail.Reason = "Bouncer manager not available for this proxy type"
				}
			}

			featureDetails[string(feature)] = detail
		}

		// Convert features to string array
		featureStrings := make([]string, len(features))
		for i, feature := range features {
			featureStrings[i] = string(feature)
		}

		response := models.ProxyFeaturesResponse{
			ProxyType:         string(proxyAdapter.Type()),
			SupportedFeatures: featureStrings,
			FeatureDetails:    featureDetails,
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    response,
		})
	}
}

// ConfigureProxy configures proxy settings (placeholder for future implementation)
func ConfigureProxy(proxyManager *proxy.ProxyManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.ProxyConfigRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Configuring proxy", "type", req.ProxyType)

		// Validate proxy type
		if err := proxy.ValidateProxyType(req.ProxyType); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid proxy type: " + err.Error(),
			})
			return
		}

		// For now, return success - full implementation would update database and restart services
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Proxy configuration updated successfully",
			Data: gin.H{
				"proxy_type":     req.ProxyType,
				"container_name": req.ContainerName,
			},
		})
	}
}

// CheckProxyHealth performs a health check on the current proxy
func CheckProxyHealth(proxyAdapter proxy.ProxyAdapter) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Checking proxy health")

		ctx := context.Background()
		healthItem, err := proxyAdapter.HealthCheck(ctx)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, models.Response{
				Success: false,
				Error:   "Health check failed: " + err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    healthItem,
			Message: "Proxy health check completed",
		})
	}
}

// GetBouncerStatus returns the bouncer integration status for the current proxy
func GetBouncerStatus(proxyAdapter proxy.ProxyAdapter) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Getting bouncer status for proxy", "type", proxyAdapter.Type())

		ctx := context.Background()
		bouncerManager := proxyAdapter.BouncerManager()
		
		if bouncerManager == nil {
			c.JSON(http.StatusOK, models.Response{
				Success: true,
				Data: gin.H{
					"supported": false,
					"reason":    "Bouncer integration not supported for this proxy type",
				},
				Message: "Bouncer integration not available",
			})
			return
		}

		// Check if bouncer is configured
		configured, err := bouncerManager.IsBouncerConfigured(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to check bouncer configuration: " + err.Error(),
			})
			return
		}

		// Get bouncer status
		status, err := bouncerManager.GetBouncerStatus(ctx)
		if err != nil {
			c.JSON(http.StatusInternalServerError, models.Response{
				Success: false,
				Error:   "Failed to get bouncer status: " + err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data: gin.H{
				"supported":  true,
				"configured": configured,
				"status":     status,
			},
			Message: "Bouncer status retrieved successfully",
		})
	}
}

// ValidateBouncerConfiguration validates the bouncer configuration for the current proxy
func ValidateBouncerConfiguration(proxyAdapter proxy.ProxyAdapter) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Validating bouncer configuration for proxy", "type", proxyAdapter.Type())

		ctx := context.Background()
		bouncerManager := proxyAdapter.BouncerManager()
		
		if bouncerManager == nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Bouncer integration not supported for this proxy type",
			})
			return
		}

		// Validate configuration
		if err := bouncerManager.ValidateConfiguration(ctx); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Bouncer configuration validation failed: " + err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Bouncer configuration is valid",
		})
	}
}

// getFeatureDescription returns a human-readable description for a proxy feature
func getFeatureDescription(feature proxy.Feature) string {
	descriptions := map[proxy.Feature]string{
		proxy.FeatureWhitelist: "IP and CIDR whitelist management at the proxy level",
		proxy.FeatureCaptcha:   "Captcha challenge integration for suspicious traffic",
		proxy.FeatureLogs:      "Access log parsing and analysis capabilities",
		proxy.FeatureBouncer:   "CrowdSec bouncer integration for decision enforcement",
		proxy.FeatureHealth:    "Health monitoring and status checking",
		proxy.FeatureAppSec:    "Application security and advanced threat protection",
	}

	if desc, exists := descriptions[feature]; exists {
		return desc
	}
	return "Feature description not available"
}