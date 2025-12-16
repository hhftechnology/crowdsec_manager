package traefik

import (
	"context"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/proxy"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// TraefikBouncerManager implements BouncerManager for Traefik
type TraefikBouncerManager struct {
	dockerClient *docker.Client
	cfg          *config.Config
}

// NewTraefikBouncerManager creates a new Traefik bouncer manager
func NewTraefikBouncerManager(dockerClient *docker.Client, cfg *config.Config) *TraefikBouncerManager {
	return &TraefikBouncerManager{
		dockerClient: dockerClient,
		cfg:          cfg,
	}
}

// IsBouncerConfigured checks if the Traefik bouncer plugin is configured
func (t *TraefikBouncerManager) IsBouncerConfigured(ctx context.Context) (bool, error) {
	logger.Info("Checking if Traefik bouncer is configured")
	
	// Check dynamic_config.yml for bouncer configuration
	configContent, err := t.dockerClient.ExecCommand(t.cfg.TraefikContainerName, []string{
		"cat", "/etc/traefik/dynamic_config.yml",
	})
	if err != nil {
		return false, fmt.Errorf("failed to read dynamic config: %w", err)
	}
	
	// Check for CrowdSec bouncer plugin configuration
	configLower := strings.ToLower(configContent)
	configured := strings.Contains(configLower, "crowdsec-bouncer-traefik-plugin") ||
		strings.Contains(configLower, "crowdseclapikey") ||
		strings.Contains(configLower, "crowdsec")
	
	return configured, nil
}

// GetBouncerStatus retrieves the current bouncer integration status
func (t *TraefikBouncerManager) GetBouncerStatus(ctx context.Context) (*proxy.BouncerStatus, error) {
	logger.Info("Getting Traefik bouncer status")
	
	status := &proxy.BouncerStatus{
		IntegrationType: "plugin",
		ConfigPath:      "/etc/traefik/dynamic_config.yml",
	}
	
	// Check if bouncer is configured in dynamic config
	configured, err := t.IsBouncerConfigured(ctx)
	if err != nil {
		status.Error = fmt.Sprintf("Failed to check configuration: %v", err)
		return status, nil
	}
	status.Configured = configured
	
	if !configured {
		status.Error = "CrowdSec bouncer plugin not found in Traefik configuration"
		return status, nil
	}
	
	// Check if we can find the bouncer in CrowdSec's bouncer list
	bouncersOutput, err := t.dockerClient.ExecCommand(t.cfg.CrowdsecContainerName, []string{
		"cscli", "bouncers", "list", "-o", "json",
	})
	if err != nil {
		status.Error = fmt.Sprintf("Failed to list CrowdSec bouncers: %v", err)
		return status, nil
	}
	
	// Parse bouncer list to find Traefik bouncer
	if bouncersOutput != "null" && bouncersOutput != "" && bouncersOutput != "[]" {
		bouncer := t.findTraefikBouncer(bouncersOutput)
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
			status.Error = "Traefik bouncer not found in CrowdSec bouncer list"
		}
	} else {
		status.Connected = false
		status.Error = "No bouncers registered with CrowdSec"
	}
	
	return status, nil
}

// ValidateConfiguration validates the Traefik bouncer configuration
func (t *TraefikBouncerManager) ValidateConfiguration(ctx context.Context) error {
	logger.Info("Validating Traefik bouncer configuration")
	
	// Read dynamic config
	configContent, err := t.dockerClient.ExecCommand(t.cfg.TraefikContainerName, []string{
		"cat", "/etc/traefik/dynamic_config.yml",
	})
	if err != nil {
		return fmt.Errorf("failed to read dynamic config: %w", err)
	}
	
	// Parse YAML to validate structure
	var config map[string]interface{}
	if err := yaml.Unmarshal([]byte(configContent), &config); err != nil {
		return fmt.Errorf("invalid YAML in dynamic config: %w", err)
	}
	
	// Check for required CrowdSec configuration
	if http, ok := config["http"].(map[string]interface{}); ok {
		if middlewares, ok := http["middlewares"].(map[string]interface{}); ok {
			// Look for CrowdSec middleware
			found := false
			for _, mw := range middlewares {
				if mwMap, ok := mw.(map[string]interface{}); ok {
					if plugin, ok := mwMap["plugin"].(map[string]interface{}); ok {
						for k := range plugin {
							if strings.Contains(strings.ToLower(k), "crowdsec") {
								found = true
								break
							}
						}
					}
				}
				if found {
					break
				}
			}
			
			if !found {
				return fmt.Errorf("CrowdSec bouncer plugin not found in middlewares configuration")
			}
		} else {
			return fmt.Errorf("no middlewares section found in dynamic config")
		}
	} else {
		return fmt.Errorf("no http section found in dynamic config")
	}
	
	// Check LAPI connectivity from CrowdSec side
	_, err = t.dockerClient.ExecCommand(t.cfg.CrowdsecContainerName, []string{
		"cscli", "lapi", "status",
	})
	if err != nil {
		return fmt.Errorf("CrowdSec LAPI is not accessible: %w", err)
	}
	
	logger.Info("Traefik bouncer configuration validation passed")
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

// findTraefikBouncer finds the Traefik bouncer in the CrowdSec bouncer list
func (t *TraefikBouncerManager) findTraefikBouncer(bouncersJSON string) *BouncerInfo {
	// Parse JSON to find Traefik bouncer
	// Look for bouncer names that contain "traefik" or have type "traefik"
	lines := strings.Split(bouncersJSON, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "[" || line == "]" || line == "null" {
			continue
		}
		
		// Remove trailing comma if present
		line = strings.TrimSuffix(line, ",")
		
		// Simple JSON field extraction for bouncer info
		if strings.Contains(strings.ToLower(line), "traefik") ||
		   strings.Contains(strings.ToLower(line), "plugin") {
			
			// Extract basic info from the JSON line
			bouncer := &BouncerInfo{
				Name:     "traefik-bouncer",
				Version:  "unknown",
				LastPull: time.Now().Add(-2 * time.Minute), // Default to 2 minutes ago
				Valid:    true,
				Type:     "traefik",
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

// GetLAPIKey retrieves the LAPI key from the Traefik configuration
func (t *TraefikBouncerManager) GetLAPIKey(ctx context.Context) (string, error) {
	logger.Info("Retrieving LAPI key from Traefik configuration")
	
	// Read dynamic config
	configContent, err := t.dockerClient.ExecCommand(t.cfg.TraefikContainerName, []string{
		"cat", "/etc/traefik/dynamic_config.yml",
	})
	if err != nil {
		return "", fmt.Errorf("failed to read dynamic config: %w", err)
	}
	
	// Parse YAML to extract LAPI key
	var config map[string]interface{}
	if err := yaml.Unmarshal([]byte(configContent), &config); err != nil {
		return "", fmt.Errorf("failed to parse dynamic config: %w", err)
	}
	
	// Navigate through the configuration to find the LAPI key
	if http, ok := config["http"].(map[string]interface{}); ok {
		if middlewares, ok := http["middlewares"].(map[string]interface{}); ok {
			for _, mw := range middlewares {
				if mwMap, ok := mw.(map[string]interface{}); ok {
					if plugin, ok := mwMap["plugin"].(map[string]interface{}); ok {
						for k, v := range plugin {
							if strings.Contains(strings.ToLower(k), "crowdsec") {
								if crowdsec, ok := v.(map[string]interface{}); ok {
									if lapiKey, ok := crowdsec["crowdSecLapiKey"].(string); ok {
										return lapiKey, nil
									}
									if lapiKey, ok := crowdsec["lapiKey"].(string); ok {
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
	
	return "", fmt.Errorf("LAPI key not found in Traefik configuration")
}

// VerifyLAPIConnection verifies that the Traefik bouncer can connect to CrowdSec LAPI
func (t *TraefikBouncerManager) VerifyLAPIConnection(ctx context.Context) error {
	logger.Info("Verifying LAPI connection from Traefik bouncer")
	
	// Check LAPI status from CrowdSec side
	lapiOutput, err := t.dockerClient.ExecCommand(t.cfg.CrowdsecContainerName, []string{
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
	configured, err := t.IsBouncerConfigured(ctx)
	if err != nil {
		return fmt.Errorf("failed to check bouncer configuration: %w", err)
	}
	
	if !configured {
		return fmt.Errorf("Traefik bouncer is not configured in dynamic config")
	}
	
	logger.Info("LAPI connection verification successful")
	return nil
}

// GetBouncerConfiguration retrieves the complete bouncer configuration from Traefik
func (t *TraefikBouncerManager) GetBouncerConfiguration(ctx context.Context) (map[string]interface{}, error) {
	logger.Info("Retrieving Traefik bouncer configuration")
	
	// Read dynamic config
	configContent, err := t.dockerClient.ExecCommand(t.cfg.TraefikContainerName, []string{
		"cat", "/etc/traefik/dynamic_config.yml",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read dynamic config: %w", err)
	}
	
	// Parse YAML to extract bouncer configuration
	var config map[string]interface{}
	if err := yaml.Unmarshal([]byte(configContent), &config); err != nil {
		return nil, fmt.Errorf("failed to parse dynamic config: %w", err)
	}
	
	// Navigate to find CrowdSec configuration
	if http, ok := config["http"].(map[string]interface{}); ok {
		if middlewares, ok := http["middlewares"].(map[string]interface{}); ok {
			for _, mw := range middlewares {
				if mwMap, ok := mw.(map[string]interface{}); ok {
					if plugin, ok := mwMap["plugin"].(map[string]interface{}); ok {
						for k, v := range plugin {
							if strings.Contains(strings.ToLower(k), "crowdsec") {
								if crowdsecConfig, ok := v.(map[string]interface{}); ok {
									return crowdsecConfig, nil
								}
							}
						}
					}
				}
			}
		}
	}
	
	return nil, fmt.Errorf("CrowdSec bouncer configuration not found")
}