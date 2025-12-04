package handlers

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"crowdsec-manager/internal/compose"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// =============================================================================
// UPDATE
// =============================================================================

// CheckForUpdates checks for updates for all services
func CheckForUpdates(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		logger.Info("Checking for updates")

		type ServiceUpdateStatus struct {
			CurrentTag      string `json:"current_tag"`
			LatestWarning   bool   `json:"latest_warning"`
			UpdateAvailable bool   `json:"update_available"`
			Error           string `json:"error,omitempty"`
		}

		status := make(map[string]ServiceUpdateStatus)

		// Map service names to container names and image names
		// Map service names to container names and image names
		type serviceInfo struct {
			containerName string
			imageName     string
		}
		services := map[string]serviceInfo{
			"traefik":  {cfg.TraefikContainerName, "traefik"},
			"crowdsec": {cfg.CrowdsecContainerName, "crowdsecurity/crowdsec"},
		}
		if cfg.IncludePangolin {
			services["pangolin"] = serviceInfo{cfg.PangolinContainerName, "fosrl/pangolin"}
		}
		if cfg.IncludeGerbil {
			services["gerbil"] = serviceInfo{cfg.GerbilContainerName, "fosrl/gerbil"}
		}

		for service, info := range services {
			s := ServiceUpdateStatus{}

			// Get current container info
			inspect, err := dockerClient.InspectContainer(info.containerName)
			if err != nil {
				logger.Warn("Failed to inspect container", "name", info.containerName, "error", err)
				s.Error = fmt.Sprintf("Container not found: %v", err)
				status[service] = s
				continue
			}

			// Extract tag
			imageParts := strings.Split(inspect.Config.Image, ":")
			if len(imageParts) >= 2 {
				s.CurrentTag = imageParts[len(imageParts)-1]
			} else {
				s.CurrentTag = "latest" // Default assumption
			}

			// Check for "latest" tag warning
			if s.CurrentTag == "latest" {
				s.LatestWarning = true
			}

			// Check for updates
			localDigest, err := dockerClient.GetLocalImageDigest(info.imageName, s.CurrentTag)
			if err != nil {
				logger.Warn("Failed to get local digest", "image", info.imageName, "tag", s.CurrentTag, "error", err)
				s.Error = "Failed to get local image digest"
			} else {
				remoteDigest, err := dockerClient.GetRemoteImageDigest(info.imageName, s.CurrentTag)
				if err != nil {
					logger.Warn("Failed to get remote digest", "image", info.imageName, "tag", s.CurrentTag, "error", err)
					s.Error = "Failed to check registry for updates"
				} else {
					if localDigest != remoteDigest {
						s.UpdateAvailable = true
					}
				}
			}

			status[service] = s
		}

		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Data:    status,
		})
	}
}

// UpdateWithCrowdSec updates the stack including CrowdSec
func UpdateWithCrowdSec(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.UpdateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Updating stack with CrowdSec", "request", req)

		// Get compose file path from environment
		composeFile := os.Getenv("COMPOSE_FILE")
		if composeFile == "" {
			composeFile = "./docker-compose.yml"
		}

		// Map of service names to their image names and requested tags
		// Map of service names to their image names and requested tags
		type serviceUpdateInfo struct {
			imageName string
			tag       string
		}
		serviceUpdates := map[string]serviceUpdateInfo{
			"traefik":  {"traefik", req.TraefikTag},
			"crowdsec": {"crowdsecurity/crowdsec", req.CrowdSecTag},
		}
		if cfg.IncludePangolin {
			serviceUpdates["pangolin"] = serviceUpdateInfo{"fosrl/pangolin", req.PangolinTag}
		}
		if cfg.IncludeGerbil {
			serviceUpdates["gerbil"] = serviceUpdateInfo{"fosrl/gerbil", req.GerbilTag}
		}

		// Map service names to container names
		serviceToContainer := map[string]string{
			"traefik":  cfg.TraefikContainerName,
			"crowdsec": cfg.CrowdsecContainerName,
		}
		if cfg.IncludePangolin {
			serviceToContainer["pangolin"] = cfg.PangolinContainerName
		}
		if cfg.IncludeGerbil {
			serviceToContainer["gerbil"] = cfg.GerbilContainerName
		}

		// Step 1: Validate all tags against registries
		logger.Info("Validating image tags against registries")
		for serviceName, update := range serviceUpdates {
			if update.tag == "" {
				logger.Debug("Skipping validation for service (no tag provided)", "service", serviceName)
				continue
			}

			logger.Info("Validating tag", "service", serviceName, "image", update.imageName, "tag", update.tag)
			if err := dockerClient.ValidateImageTag(update.imageName, update.tag); err != nil {
				c.JSON(http.StatusBadRequest, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Invalid tag for %s: %v", serviceName, err),
				})
				return
			}
		}

		// Step 2: Update docker-compose.yml file
		logger.Info("Updating docker-compose.yml file")
		composeTags := make(map[string]string)
		for serviceName, update := range serviceUpdates {
			if update.tag != "" {
				composeTags[serviceName] = update.tag
			}
		}

		if len(composeTags) > 0 {
			if err := compose.UpdateComposeFileTags(composeFile, composeTags); err != nil {
				logger.Error("Failed to update compose file", "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   "Failed to update docker-compose.yml: " + err.Error(),
				})
				return
			}
			logger.Info("Successfully updated docker-compose.yml")
		}

		// Step 3: Pull new images
		logger.Info("Pulling new images")
		for serviceName, update := range serviceUpdates {
			if update.tag == "" {
				continue
			}

			logger.Info("Pulling image", "service", serviceName, "image", update.imageName, "tag", update.tag)
			if err := dockerClient.PullImage(update.imageName, update.tag); err != nil {
				logger.Error("Failed to pull image", "service", serviceName, "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Failed to pull image for %s: %v", serviceName, err),
				})
				return
			}
		}

		// Step 4: Recreate containers with new images
		logger.Info("Recreating containers")
		services := []string{"traefik", "crowdsec"}
		if cfg.IncludePangolin {
			services = append(services, "pangolin")
		}
		if cfg.IncludeGerbil {
			services = append(services, "gerbil")
		}

		for _, service := range services {
			// Only recreate if a tag was provided for this service
			update, exists := serviceUpdates[service]
			if !exists || update.tag == "" {
				logger.Debug("Skipping container recreation (no update)", "service", service)
				continue
			}

			logger.Info("Recreating container", "service", service)
			containerName := serviceToContainer[service]
			if err := dockerClient.RecreateContainer(containerName); err != nil {
				logger.Error("Failed to recreate container", "service", service, "container", containerName, "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Failed to recreate container %s: %v", containerName, err),
				})
				return
			}
		}

		logger.Info("Stack updated successfully with CrowdSec")
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Stack updated successfully with CrowdSec",
		})
	}
}

// UpdateWithoutCrowdSec updates the stack without CrowdSec
func UpdateWithoutCrowdSec(dockerClient *docker.Client, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req models.UpdateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.Response{
				Success: false,
				Error:   "Invalid request: " + err.Error(),
			})
			return
		}

		logger.Info("Updating stack without CrowdSec", "request", req)

		// Get compose file path from environment
		composeFile := os.Getenv("COMPOSE_FILE")
		if composeFile == "" {
			composeFile = "./docker-compose.yml"
		}

		// Map of service names to their image names and requested tags (excluding CrowdSec)
		// Map of service names to their image names and requested tags (excluding CrowdSec)
		type serviceUpdateInfo struct {
			imageName string
			tag       string
		}
		serviceUpdates := map[string]serviceUpdateInfo{
			"traefik": {"traefik", req.TraefikTag},
		}
		if cfg.IncludePangolin {
			serviceUpdates["pangolin"] = serviceUpdateInfo{"fosrl/pangolin", req.PangolinTag}
		}
		if cfg.IncludeGerbil {
			serviceUpdates["gerbil"] = serviceUpdateInfo{"fosrl/gerbil", req.GerbilTag}
		}

		// Map service names to container names
		serviceToContainer := map[string]string{
			"traefik": cfg.TraefikContainerName,
		}
		if cfg.IncludePangolin {
			serviceToContainer["pangolin"] = cfg.PangolinContainerName
		}
		if cfg.IncludeGerbil {
			serviceToContainer["gerbil"] = cfg.GerbilContainerName
		}

		// Step 1: Validate all tags against registries
		logger.Info("Validating image tags against registries")
		for serviceName, update := range serviceUpdates {
			if update.tag == "" {
				logger.Debug("Skipping validation for service (no tag provided)", "service", serviceName)
				continue
			}

			logger.Info("Validating tag", "service", serviceName, "image", update.imageName, "tag", update.tag)
			if err := dockerClient.ValidateImageTag(update.imageName, update.tag); err != nil {
				c.JSON(http.StatusBadRequest, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Invalid tag for %s: %v", serviceName, err),
				})
				return
			}
		}

		// Step 2: Update docker-compose.yml file
		logger.Info("Updating docker-compose.yml file")
		composeTags := make(map[string]string)
		for serviceName, update := range serviceUpdates {
			if update.tag != "" {
				composeTags[serviceName] = update.tag
			}
		}

		if len(composeTags) > 0 {
			if err := compose.UpdateComposeFileTags(composeFile, composeTags); err != nil {
				logger.Error("Failed to update compose file", "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   "Failed to update docker-compose.yml: " + err.Error(),
				})
				return
			}
			logger.Info("Successfully updated docker-compose.yml")
		}

		// Step 3: Pull new images
		logger.Info("Pulling new images")
		for serviceName, update := range serviceUpdates {
			if update.tag == "" {
				continue
			}

			logger.Info("Pulling image", "service", serviceName, "image", update.imageName, "tag", update.tag)
			if err := dockerClient.PullImage(update.imageName, update.tag); err != nil {
				logger.Error("Failed to pull image", "service", serviceName, "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Failed to pull image for %s: %v", serviceName, err),
				})
				return
			}
		}

		// Step 4: Recreate containers with new images
		logger.Info("Recreating containers")
		services := []string{"traefik"}
		if cfg.IncludePangolin {
			services = append(services, "pangolin")
		}
		if cfg.IncludeGerbil {
			services = append(services, "gerbil")
		}

		for _, service := range services {
			// Only recreate if a tag was provided for this service
			update, exists := serviceUpdates[service]
			if !exists || update.tag == "" {
				logger.Debug("Skipping container recreation (no update)", "service", service)
				continue
			}

			logger.Info("Recreating container", "service", service)
			containerName := serviceToContainer[service]
			if err := dockerClient.RecreateContainer(containerName); err != nil {
				logger.Error("Failed to recreate container", "service", service, "container", containerName, "error", err)
				c.JSON(http.StatusInternalServerError, models.Response{
					Success: false,
					Error:   fmt.Sprintf("Failed to recreate container %s: %v", containerName, err),
				})
				return
			}
		}

		logger.Info("Stack updated successfully without CrowdSec")
		c.JSON(http.StatusOK, models.Response{
			Success: true,
			Message: "Stack updated successfully without CrowdSec",
		})
	}
}
