package handlers

import (
	"crowdsec-manager/internal/api/dto"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

// ValidateComplete performs complete validation of all layers
// GET /api/config/validate/complete
func ValidateComplete(cfg *config.Config, dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Starting complete validation")
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Panic in ValidateComplete", "error", r)
				c.JSON(http.StatusInternalServerError, dto.ErrMsg(fmt.Sprintf("Internal Panic: %v", r)))
			}
		}()

		validator := config.NewValidator(cfg, dockerClient.GetClient())

		result, err := validator.ValidateComplete()
		if err != nil {
			logger.Error("Validation failed", "error", err)
			c.JSON(http.StatusInternalServerError, dto.Err(err))
			return
		}

		logger.Info("Validation completed successfully", "valid", result.Valid, "overall_status", result.Summary.OverallStatus)
		c.JSON(http.StatusOK, dto.Success(result))
	}
}


// ValidateEnv validates environment variables only
// POST /api/config/env/validate
func ValidateEnv(cfg *config.Config, dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		validator := config.NewValidator(cfg, dockerClient.GetClient())
		envValidation := validator.ValidateEnvironmentVariables()

		c.JSON(http.StatusOK, dto.Success(envValidation))
	}
}

// GetEnvVars returns all current environment variables
// GET /api/config/env
func GetEnvVars(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		requirements := config.GetProxyRequirementsFromConfig(cfg)

		envVars := make(map[string]string)
		allVars := append(requirements.RequiredEnvVars, requirements.OptionalEnvVars...)

		for _, envVar := range allVars {
			envVars[envVar] = os.Getenv(envVar)
		}

		c.JSON(http.StatusOK, dto.Success(gin.H{
			"proxy_type": cfg.ProxyType,
			"env_vars":   envVars,
		}))
	}
}

// GetRequiredEnvVars returns required environment variables for a proxy type
// GET /api/config/env/required/:proxyType
func GetRequiredEnvVars(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		proxyType := c.Param("proxyType")

		if proxyType == "" {
			proxyType = cfg.ProxyType
		}

		// Create a temporary config with the requested proxy type to get dynamic requirements
		tempCfg := *cfg
		tempCfg.ProxyType = proxyType
		requirements := config.GetProxyRequirementsFromConfig(&tempCfg)

		c.JSON(http.StatusOK, dto.Success(gin.H{
			"proxy_type": proxyType,
			"required":   requirements.RequiredEnvVars,
			"optional":   requirements.OptionalEnvVars,
			"features":   requirements.Features,
		}))
	}
}

// ValidateHostPaths validates host paths only
// GET /api/config/paths/validate/host
func ValidateHostPaths(cfg *config.Config, dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		validator := config.NewValidator(cfg, dockerClient.GetClient())
		result := validator.ValidateHostPaths()

		c.JSON(http.StatusOK, dto.Success(result))
	}
}

// ValidateVolumeMappings validates Docker volume mappings
// GET /api/config/volumes/validate
func ValidateVolumeMappings(cfg *config.Config, dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		validator := config.NewValidator(cfg, dockerClient.GetClient())
		result := validator.ValidateVolumeMappings()

		c.JSON(http.StatusOK, dto.Success(result))
	}
}

// ValidateContainerPaths validates container paths
// GET /api/config/paths/validate/container
func ValidateContainerPaths(cfg *config.Config, dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		validator := config.NewValidator(cfg, dockerClient.GetClient())
		result := validator.ValidateContainerPaths()

		c.JSON(http.StatusOK, dto.Success(result))
	}
}

// GetSuggestions returns suggestions for fixing validation issues
// GET /api/config/suggestions
func GetSuggestions(cfg *config.Config, dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		validator := config.NewValidator(cfg, dockerClient.GetClient())

		// Run complete validation first
		result, err := validator.ValidateComplete()
		if err != nil {
			c.JSON(http.StatusInternalServerError, dto.Err(err))
			return
		}

		c.JSON(http.StatusOK, dto.Success(gin.H{
			"suggestions": result.Suggestions,
			"summary":     result.Summary,
		}))
	}
}

// GetProxyRequirements returns requirements for all or specific proxy type
// GET /api/config/requirements
// GET /api/config/requirements/:proxyType
func GetProxyRequirements(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		proxyType := c.Param("proxyType")

		if proxyType == "" {
			// Return all proxy requirements
			allReqs := config.GetAllProxyRequirements()
			c.JSON(http.StatusOK, dto.Success(allReqs))
			return
		}

		// Return specific proxy requirements with actual config values
		tempCfg := *cfg
		tempCfg.ProxyType = proxyType
		requirements := config.GetProxyRequirementsFromConfig(&tempCfg)
		c.JSON(http.StatusOK, dto.Success(requirements))
	}
}

// ExportEnvFile exports a suggested .env file
// GET /api/config/export/env
func ExportEnvFile(cfg *config.Config, dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		validator := config.NewValidator(cfg, dockerClient.GetClient())

		// Run complete validation
		result, err := validator.ValidateComplete()
		if err != nil {
			c.JSON(http.StatusInternalServerError, dto.Err(err))
			return
		}

		// Generate .env file content
		engine := config.NewSuggestionEngine(cfg.ProxyType)
		envContent := engine.GenerateEnvFile(result, result.Suggestions)

		// Return as downloadable file
		c.Header("Content-Type", "text/plain")
		c.Header("Content-Disposition", "attachment; filename=\".env\"")
		c.String(http.StatusOK, envContent)
	}
}

// TestPath tests if a specific path is accessible
// POST /api/config/paths/test
func TestPath() gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			Path string `json:"path"`
			Type string `json:"type"` // host, container
		}

		if err := c.BindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, dto.ErrMsg("Invalid request body"))
			return
		}

		if request.Path == "" {
			c.JSON(http.StatusBadRequest, dto.ErrMsg("Path is required"))
			return
		}

		var result map[string]interface{}

		if request.Type == "host" || request.Type == "" {
			// Test host path
			info, err := os.Stat(request.Path)
			exists := err == nil
			isDir := exists && info.IsDir()

			result = map[string]interface{}{
				"path":       request.Path,
				"exists":     exists,
				"is_dir":     isDir,
				"accessible": exists,
				"type":       "host",
			}

			if err != nil {
				result["error"] = err.Error()
			}
		}

		c.JSON(http.StatusOK, dto.Success(result))
	}
}

// GetValidationSummary returns a quick validation summary
// GET /api/config/summary
func GetValidationSummary(cfg *config.Config, dockerClient *docker.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		validator := config.NewValidator(cfg, dockerClient.GetClient())

		result, err := validator.ValidateComplete()
		if err != nil {
			c.JSON(http.StatusInternalServerError, dto.Err(err))
			return
		}

		summary := gin.H{
			"proxy_type":        result.ProxyType,
			"overall_status":    result.Summary.OverallStatus,
			"ready_to_deploy":   result.Summary.ReadyToDeploy,
			"total_checks":      result.Summary.TotalChecks,
			"passed_checks":     result.Summary.PassedChecks,
			"failed_checks":     result.Summary.FailedChecks,
			"warning_checks":    result.Summary.WarningChecks,
			"suggestions_count": len(result.Suggestions),
			"timestamp":         result.Timestamp,
		}

		c.JSON(http.StatusOK, dto.Success(summary))
	}
}
