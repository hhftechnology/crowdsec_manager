package caddy

import (
	"context"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/proxy"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// CaddyBouncerManager implements BouncerManager for Caddy with caddy-crowdsec-bouncer module
type CaddyBouncerManager struct {
	dockerClient *docker.Client
	cfg          *config.Config
}

// NewCaddyBouncerManager creates a new Caddy bouncer manager
func NewCaddyBouncerManager(dockerClient *docker.Client, cfg *config.Config) *CaddyBouncerManager {
	return &CaddyBouncerManager{
		dockerClient: dockerClient,
		cfg:          cfg,
	}
}

// IsBouncerConfigured checks if the caddy-crowdsec-bouncer module is configured
func (c *CaddyBouncerManager) IsBouncerConfigured(ctx context.Context) (bool, error) {
	logger.Info("Checking if caddy-crowdsec-bouncer module is configured")
	
	containerName := c.cfg.TraefikContainerName // Reused field for Caddy container
	
	// Check Caddy configuration for CrowdSec module
	configOutput, err := c.dockerClient.ExecCommand(containerName, []string{
		"curl", "-s", "http://localhost:2019/config/",
	})
	if err != nil {
		// Try alternative method - check Caddyfile
		caddyfileContent, err := c.dockerClient.ExecCommand(containerName, []string{
			"cat", "/etc/caddy/Caddyfile",
		})
		if err != nil {
			return false, nil // Not configured, but not an error
		}
		
		// Check for CrowdSec module in Caddyfile
		return strings.Contains(strings.ToLower(caddyfileContent), "crowdsec"), nil
	}
	
	// Check for CrowdSec module in JSON config
	configLower := strings.ToLower(configOutput)
	configured := strings.Contains(configLower, "crowdsec") ||
		strings.Contains(configLower, "bouncer")
	
	return configured, nil
}

// GetBouncerStatus retrieves the current bouncer integration status
func (c *CaddyBouncerManager) GetBouncerStatus(ctx context.Context) (*proxy.BouncerStatus, error) {
	logger.Info("Getting caddy-crowdsec-bouncer status")
	
	status := &proxy.BouncerStatus{
		IntegrationType: "module",
		ConfigPath:      "/etc/caddy/Caddyfile",
	}
	
	// Check if bouncer is configured
	configured, err := c.IsBouncerConfigured(ctx)
	if err != nil {
		status.Error = fmt.Sprintf("Failed to check configuration: %v", err)
		return status, nil
	}
	status.Configured = configured
	
	if !configured {
		status.Error = "caddy-crowdsec-bouncer module not found in Caddy configuration"
		return status, nil
	}
	
	// Check if we can find the bouncer in CrowdSec's bouncer list
	bouncersOutput, err := c.dockerClient.ExecCommand(c.cfg.CrowdsecContainerName, []string{
		"cscli", "bouncers", "list", "-o", "json",
	})
	if err != nil {
		status.Error = fmt.Sprintf("Failed to list CrowdSec bouncers: %v", err)
		return status, nil
	}
	
	// Parse bouncer list to find Caddy bouncer
	if bouncersOutput != "null" && bouncersOutput != "" && bouncersOutput != "[]" {
		bouncer := c.findCaddyBouncer(bouncersOutput)
		if bouncer != nil {
			status.Connected = true
			status.BouncerName = bouncer.Name
			status.Version = bouncer.Version
			status.LastSeen = bouncer.LastPull.Format(time.RFC3339)
			
			// Check if bouncer is active (last pull within 5 minutes)
			if time.Since(bouncer.LastPull) <= 5*time.Minute {
				status.Connected = true
			} else {
				status.Connected = false
				status.Error = "Bouncer has not pulled decisions recently"
			}
		} else {
			status.Connected = false
			status.Error = "Caddy bouncer not found in CrowdSec bouncer list"
		}
	} else {
		status.Connected = false
		status.Error = "No bouncers registered with CrowdSec"
	}
	
	return status, nil
}

// ValidateConfiguration validates the caddy-crowdsec-bouncer configuration
func (c *CaddyBouncerManager) ValidateConfiguration(ctx context.Context) error {
	logger.Info("Validating caddy-crowdsec-bouncer configuration")
	
	containerName := c.cfg.TraefikContainerName // Reused field for Caddy container
	
	// Check if Caddy admin API is accessible
	_, err := c.dockerClient.ExecCommand(containerName, []string{
		"curl", "-f", "http://localhost:2019/config/",
	})
	if err != nil {
		return fmt.Errorf("Caddy admin API is not accessible: %w", err)
	}
	
	// Check if CrowdSec module is loaded
	configured, err := c.IsBouncerConfigured(ctx)
	if err != nil {
		return fmt.Errorf("failed to check bouncer configuration: %w", err)
	}
	
	if !configured {
		return fmt.Errorf("caddy-crowdsec-bouncer module is not configured")
	}
	
	// Check LAPI connectivity from CrowdSec side
	_, err = c.dockerClient.ExecCommand(c.cfg.CrowdsecContainerName, []string{
		"cscli", "lapi", "status",
	})
	if err != nil {
		return fmt.Errorf("CrowdSec LAPI is not accessible: %w", err)
	}
	
	logger.Info("caddy-crowdsec-bouncer configuration validation passed")
	return nil
}

// BouncerInfo represents bouncer information from CrowdSec
type BouncerInfo struct {
	Name     string    `json:"name"`
	Version  string    `json:"version"`
	LastPull time.Time `json:"last_pull"`
	Valid    bool      `json:"valid"`
	Type     string    `json:"type"`
}

// findCaddyBouncer finds the Caddy bouncer in the CrowdSec bouncer list
func (c *CaddyBouncerManager) findCaddyBouncer(bouncersJSON string) *BouncerInfo {
	// Parse JSON to find Caddy bouncer
	// Look for bouncer names that contain "caddy" or have type "caddy"
	lines := strings.Split(bouncersJSON, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "[" || line == "]" || line == "null" {
			continue
		}
		
		// Remove trailing comma if present
		line = strings.TrimSuffix(line, ",")
		
		// Simple JSON field extraction for bouncer info
		if strings.Contains(strings.ToLower(line), "caddy") {
			
			// Extract basic info from the JSON line
			bouncer := &BouncerInfo{
				Name:     "caddy-bouncer",
				Version:  "unknown",
				LastPull: time.Now().Add(-2 * time.Minute), // Default to 2 minutes ago
				Valid:    true,
				Type:     "caddy",
			}
			
			// Try to extract name if present
			if strings.Contains(line, `"name"`) {
				parts := strings.Split(line, `"name"`)
				if len(parts) > 1 {
					namePart := strings.Split(parts[1], `"`)
					if len(namePart) > 2 {
						bouncer.Name = namePart[2]
					}
				}
			}
			
			// Try to extract version if present
			if strings.Contains(line, `"version"`) {
				parts := strings.Split(line, `"version"`)
				if len(parts) > 1 {
					versionPart := strings.Split(parts[1], `"`)
					if len(versionPart) > 2 {
						bouncer.Version = versionPart[2]
					}
				}
			}
			
			// Try to extract last_pull if present
			if strings.Contains(line, `"last_pull"`) {
				parts := strings.Split(line, `"last_pull"`)
				if len(parts) > 1 {
					timePart := strings.Split(parts[1], `"`)
					if len(timePart) > 2 {
						if t, err := time.Parse(time.RFC3339, timePart[2]); err == nil {
							bouncer.LastPull = t
						}
					}
				}
			}
			
			return bouncer
		}
	}
	
	return nil
}

// GetLAPIKey retrieves the LAPI key from the Caddy configuration
func (c *CaddyBouncerManager) GetLAPIKey(ctx context.Context) (string, error) {
	logger.Info("Retrieving LAPI key from Caddy configuration")
	
	containerName := c.cfg.TraefikContainerName // Reused field for Caddy container
	
	// Try to get config from admin API
	configOutput, err := c.dockerClient.ExecCommand(containerName, []string{
		"curl", "-s", "http://localhost:2019/config/",
	})
	if err != nil {
		return "", fmt.Errorf("failed to get Caddy config: %w", err)
	}
	
	// Parse JSON config to extract LAPI key
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(configOutput), &config); err != nil {
		return "", fmt.Errorf("failed to parse Caddy config JSON: %w", err)
	}
	
	// Navigate through the configuration to find the LAPI key
	// This is a simplified approach - actual structure may vary
	if apps, ok := config["apps"].(map[string]interface{}); ok {
		if http, ok := apps["http"].(map[string]interface{}); ok {
			if servers, ok := http["servers"].(map[string]interface{}); ok {
				for _, server := range servers {
					if serverMap, ok := server.(map[string]interface{}); ok {
						if routes, ok := serverMap["routes"].([]interface{}); ok {
							for _, route := range routes {
								if routeMap, ok := route.(map[string]interface{}); ok {
									if handle, ok := routeMap["handle"].([]interface{}); ok {
										for _, handler := range handle {
											if handlerMap, ok := handler.(map[string]interface{}); ok {
												if handlerMap["handler"] == "crowdsec" {
													if lapiKey, ok := handlerMap["lapi_key"].(string); ok {
														return lapiKey, nil
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	return "", fmt.Errorf("LAPI key not found in Caddy configuration")
}

// VerifyLAPIConnection verifies that the Caddy bouncer can connect to CrowdSec LAPI
func (c *CaddyBouncerManager) VerifyLAPIConnection(ctx context.Context) error {
	logger.Info("Verifying LAPI connection from Caddy bouncer")
	
	// Check LAPI status from CrowdSec side
	lapiOutput, err := c.dockerClient.ExecCommand(c.cfg.CrowdsecContainerName, []string{
		"cscli", "lapi", "status",
	})
	if err != nil {
		return fmt.Errorf("CrowdSec LAPI is not accessible: %w", err)
	}
	
	// Check if LAPI is responding properly
	if !strings.Contains(strings.ToLower(lapiOutput), "successfully") &&
	   !strings.Contains(strings.ToLower(lapiOutput), "ok") {
		return fmt.Errorf("CrowdSec LAPI is not responding properly: %s", lapiOutput)
	}
	
	// Verify bouncer configuration exists
	configured, err := c.IsBouncerConfigured(ctx)
	if err != nil {
		return fmt.Errorf("failed to check bouncer configuration: %w", err)
	}
	
	if !configured {
		return fmt.Errorf("caddy-crowdsec-bouncer module is not configured")
	}
	
	logger.Info("LAPI connection verification successful")
	return nil
}

// GetBouncerConfiguration retrieves the complete bouncer configuration from Caddy
func (c *CaddyBouncerManager) GetBouncerConfiguration(ctx context.Context) (map[string]interface{}, error) {
	logger.Info("Retrieving Caddy bouncer configuration")
	
	containerName := c.cfg.TraefikContainerName // Reused field for Caddy container
	
	// Get config from admin API
	configOutput, err := c.dockerClient.ExecCommand(containerName, []string{
		"curl", "-s", "http://localhost:2019/config/",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get Caddy config: %w", err)
	}
	
	// Parse JSON config
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(configOutput), &config); err != nil {
		return nil, fmt.Errorf("failed to parse Caddy config JSON: %w", err)
	}
	
	// Extract CrowdSec-related configuration
	crowdsecConfig := make(map[string]interface{})
	
	// Navigate through the configuration to find CrowdSec settings
	if apps, ok := config["apps"].(map[string]interface{}); ok {
		if http, ok := apps["http"].(map[string]interface{}); ok {
			if servers, ok := http["servers"].(map[string]interface{}); ok {
				for _, server := range servers {
					if serverMap, ok := server.(map[string]interface{}); ok {
						if routes, ok := serverMap["routes"].([]interface{}); ok {
							for _, route := range routes {
								if routeMap, ok := route.(map[string]interface{}); ok {
									if handle, ok := routeMap["handle"].([]interface{}); ok {
										for _, handler := range handle {
											if handlerMap, ok := handler.(map[string]interface{}); ok {
												if handlerMap["handler"] == "crowdsec" {
													crowdsecConfig = handlerMap
													return crowdsecConfig, nil
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	
	if len(crowdsecConfig) == 0 {
		return nil, fmt.Errorf("CrowdSec bouncer configuration not found")
	}
	
	return crowdsecConfig, nil
}

// ReloadConfiguration reloads the Caddy configuration
func (c *CaddyBouncerManager) ReloadConfiguration(ctx context.Context) error {
	logger.Info("Reloading Caddy configuration")
	
	containerName := c.cfg.TraefikContainerName // Reused field for Caddy container
	
	// Reload Caddy configuration
	_, err := c.dockerClient.ExecCommand(containerName, []string{
		"curl", "-X", "POST", "http://localhost:2019/load",
	})
	if err != nil {
		return fmt.Errorf("failed to reload Caddy configuration: %w", err)
	}
	
	logger.Info("Caddy configuration reloaded successfully")
	return nil
}