package nginx

import (
	"context"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/proxy"
	"fmt"
	"strings"
	"time"
)

// NginxBouncerManager implements BouncerManager for Nginx Proxy Manager with cs-nginx-bouncer
type NginxBouncerManager struct {
	dockerClient *docker.Client
	cfg          *config.Config
}

// NewNginxBouncerManager creates a new Nginx bouncer manager
func NewNginxBouncerManager(dockerClient *docker.Client, cfg *config.Config) *NginxBouncerManager {
	return &NginxBouncerManager{
		dockerClient: dockerClient,
		cfg:          cfg,
	}
}

// IsBouncerConfigured checks if the cs-nginx-bouncer is configured
func (n *NginxBouncerManager) IsBouncerConfigured(ctx context.Context) (bool, error) {
	logger.Info("Checking if cs-nginx-bouncer is configured")
	
	containerName := n.cfg.TraefikContainerName // Reused field for NPM container
	
	// Check if cs-nginx-bouncer configuration exists
	// cs-nginx-bouncer typically uses /etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf
	_, err := n.dockerClient.ExecCommand(containerName, []string{
		"cat", "/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf",
	})
	if err != nil {
		// Try alternative locations
		_, err = n.dockerClient.ExecCommand(containerName, []string{
			"find", "/etc", "-name", "*nginx*bouncer*", "-type", "f",
		})
		if err != nil {
			return false, nil // Not configured, but not an error
		}
	}
	
	return true, nil
}

// GetBouncerStatus retrieves the current bouncer integration status
func (n *NginxBouncerManager) GetBouncerStatus(ctx context.Context) (*proxy.BouncerStatus, error) {
	logger.Info("Getting cs-nginx-bouncer status")
	
	status := &proxy.BouncerStatus{
		IntegrationType: "module",
		ConfigPath:      "/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf",
	}
	
	// Check if bouncer is configured
	configured, err := n.IsBouncerConfigured(ctx)
	if err != nil {
		status.Error = fmt.Sprintf("Failed to check configuration: %v", err)
		return status, nil
	}
	status.Configured = configured
	
	if !configured {
		status.Error = "cs-nginx-bouncer configuration not found"
		return status, nil
	}
	
	// Check if we can find the bouncer in CrowdSec's bouncer list
	bouncersOutput, err := n.dockerClient.ExecCommand(n.cfg.CrowdsecContainerName, []string{
		"cscli", "bouncers", "list", "-o", "json",
	})
	if err != nil {
		status.Error = fmt.Sprintf("Failed to list CrowdSec bouncers: %v", err)
		return status, nil
	}
	
	// Parse bouncer list to find Nginx bouncer
	if bouncersOutput != "null" && bouncersOutput != "" && bouncersOutput != "[]" {
		bouncer := n.findNginxBouncer(bouncersOutput)
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
			status.Error = "Nginx bouncer not found in CrowdSec bouncer list"
		}
	} else {
		status.Connected = false
		status.Error = "No bouncers registered with CrowdSec"
	}
	
	return status, nil
}

// ValidateConfiguration validates the cs-nginx-bouncer configuration
func (n *NginxBouncerManager) ValidateConfiguration(ctx context.Context) error {
	logger.Info("Validating cs-nginx-bouncer configuration")
	
	containerName := n.cfg.TraefikContainerName // Reused field for NPM container
	
	// Check if configuration file exists and is readable
	configContent, err := n.dockerClient.ExecCommand(containerName, []string{
		"cat", "/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf",
	})
	if err != nil {
		return fmt.Errorf("cs-nginx-bouncer configuration file not found or not readable: %w", err)
	}
	
	// Basic validation - check for required fields
	requiredFields := []string{"api_url", "api_key"}
	for _, field := range requiredFields {
		if !strings.Contains(configContent, field) {
			return fmt.Errorf("required field '%s' not found in bouncer configuration", field)
		}
	}
	
	// Check LAPI connectivity from CrowdSec side
	_, err = n.dockerClient.ExecCommand(n.cfg.CrowdsecContainerName, []string{
		"cscli", "lapi", "status",
	})
	if err != nil {
		return fmt.Errorf("CrowdSec LAPI is not accessible: %w", err)
	}
	
	logger.Info("cs-nginx-bouncer configuration validation passed")
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

// findNginxBouncer finds the Nginx bouncer in the CrowdSec bouncer list
func (n *NginxBouncerManager) findNginxBouncer(bouncersJSON string) *BouncerInfo {
	// Parse JSON to find Nginx bouncer
	// Look for bouncer names that contain "nginx" or have type "nginx"
	lines := strings.Split(bouncersJSON, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "[" || line == "]" || line == "null" {
			continue
		}
		
		// Remove trailing comma if present
		line = strings.TrimSuffix(line, ",")
		
		// Simple JSON field extraction for bouncer info
		if strings.Contains(strings.ToLower(line), "nginx") {
			
			// Extract basic info from the JSON line
			bouncer := &BouncerInfo{
				Name:     "nginx-bouncer",
				Version:  "unknown",
				LastPull: time.Now().Add(-2 * time.Minute), // Default to 2 minutes ago
				Valid:    true,
				Type:     "nginx",
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

// GetLAPIKey retrieves the LAPI key from the cs-nginx-bouncer configuration
func (n *NginxBouncerManager) GetLAPIKey(ctx context.Context) (string, error) {
	logger.Info("Retrieving LAPI key from cs-nginx-bouncer configuration")
	
	containerName := n.cfg.TraefikContainerName // Reused field for NPM container
	
	// Read bouncer config
	configContent, err := n.dockerClient.ExecCommand(containerName, []string{
		"cat", "/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf",
	})
	if err != nil {
		return "", fmt.Errorf("failed to read bouncer config: %w", err)
	}
	
	// Extract API key from config
	lines := strings.Split(configContent, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "api_key") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}
	
	return "", fmt.Errorf("API key not found in bouncer configuration")
}

// VerifyLAPIConnection verifies that the cs-nginx-bouncer can connect to CrowdSec LAPI
func (n *NginxBouncerManager) VerifyLAPIConnection(ctx context.Context) error {
	logger.Info("Verifying LAPI connection from cs-nginx-bouncer")
	
	// Check LAPI status from CrowdSec side
	lapiOutput, err := n.dockerClient.ExecCommand(n.cfg.CrowdsecContainerName, []string{
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
	configured, err := n.IsBouncerConfigured(ctx)
	if err != nil {
		return fmt.Errorf("failed to check bouncer configuration: %w", err)
	}
	
	if !configured {
		return fmt.Errorf("cs-nginx-bouncer is not configured")
	}
	
	logger.Info("LAPI connection verification successful")
	return nil
}

// GetBouncerConfiguration retrieves the complete bouncer configuration
func (n *NginxBouncerManager) GetBouncerConfiguration(ctx context.Context) (map[string]interface{}, error) {
	logger.Info("Retrieving cs-nginx-bouncer configuration")
	
	containerName := n.cfg.TraefikContainerName // Reused field for NPM container
	
	// Read bouncer config
	configContent, err := n.dockerClient.ExecCommand(containerName, []string{
		"cat", "/etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read bouncer config: %w", err)
	}
	
	// Parse configuration into map
	config := make(map[string]interface{})
	lines := strings.Split(configContent, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			config[key] = value
		}
	}
	
	return config, nil
}

// ConfigureAcquisition configures CrowdSec acquis.yaml for NPM log collection
func (n *NginxBouncerManager) ConfigureAcquisition(ctx context.Context) error {
	logger.Info("Configuring CrowdSec acquisition for Nginx Proxy Manager logs")
	
	// Read current acquis.yaml
	acquisContent, err := n.dockerClient.ExecCommand(n.cfg.CrowdsecContainerName, []string{
		"cat", "/etc/crowdsec/acquis.yaml",
	})
	if err != nil {
		// If file doesn't exist, create a basic one
		acquisContent = ""
	}
	
	// Check if NPM log acquisition is already configured
	if strings.Contains(acquisContent, "/data/logs/proxy-host-*.log") {
		logger.Info("NPM log acquisition already configured")
		return nil
	}
	
	// Add NPM log acquisition configuration
	npmAcquisConfig := `
---
# Nginx Proxy Manager logs
filenames:
  - /data/logs/proxy-host-*.log
labels:
  type: nginx
`
	
	newAcquisContent := acquisContent + npmAcquisConfig
	
	// Write updated acquis.yaml
	_, err = n.dockerClient.ExecCommand(n.cfg.CrowdsecContainerName, []string{
		"sh", "-c", fmt.Sprintf("echo '%s' > /etc/crowdsec/acquis.yaml", strings.ReplaceAll(newAcquisContent, "'", "'\\''")),
	})
	if err != nil {
		return fmt.Errorf("failed to update acquis.yaml: %w", err)
	}
	
	// Reload CrowdSec configuration
	_, err = n.dockerClient.ExecCommand(n.cfg.CrowdsecContainerName, []string{
		"cscli", "config", "reload",
	})
	if err != nil {
		logger.Warn("Failed to reload CrowdSec config", "error", err)
	}
	
	logger.Info("NPM log acquisition configured successfully")
	return nil
}