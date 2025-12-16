package haproxy

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

// HAProxyBouncerManager implements BouncerManager for HAProxy with cs-haproxy-bouncer SPOA integration
type HAProxyBouncerManager struct {
	dockerClient *docker.Client
	cfg          *config.Config
}

// NewHAProxyBouncerManager creates a new HAProxy bouncer manager
func NewHAProxyBouncerManager(dockerClient *docker.Client, cfg *config.Config) *HAProxyBouncerManager {
	return &HAProxyBouncerManager{
		dockerClient: dockerClient,
		cfg:          cfg,
	}
}

// IsBouncerConfigured checks if the cs-haproxy-bouncer SPOA is configured
func (h *HAProxyBouncerManager) IsBouncerConfigured(ctx context.Context) (bool, error) {
	logger.Info("Checking if cs-haproxy-bouncer SPOA is configured")
	
	containerName := h.cfg.TraefikContainerName // Reused field for HAProxy container
	
	// Check HAProxy configuration for SPOA configuration
	configContent, err := h.dockerClient.ExecCommand(containerName, []string{
		"cat", "/usr/local/etc/haproxy/haproxy.cfg",
	})
	if err != nil {
		// Try alternative location
		configContent, err = h.dockerClient.ExecCommand(containerName, []string{
			"cat", "/etc/haproxy/haproxy.cfg",
		})
		if err != nil {
			return false, nil // Not configured, but not an error
		}
	}
	
	// Check for SPOA configuration in HAProxy config
	configLower := strings.ToLower(configContent)
	configured := strings.Contains(configLower, "spoe-agent") &&
		strings.Contains(configLower, "crowdsec") ||
		strings.Contains(configLower, "spoe-message") &&
		strings.Contains(configLower, "crowdsec")
	
	return configured, nil
}

// GetBouncerStatus retrieves the current bouncer integration status
func (h *HAProxyBouncerManager) GetBouncerStatus(ctx context.Context) (*proxy.BouncerStatus, error) {
	logger.Info("Getting cs-haproxy-bouncer SPOA status")
	
	status := &proxy.BouncerStatus{
		IntegrationType: "spoa",
		ConfigPath:      "/usr/local/etc/haproxy/haproxy.cfg",
	}
	
	// Check if bouncer is configured
	configured, err := h.IsBouncerConfigured(ctx)
	if err != nil {
		status.Error = fmt.Sprintf("Failed to check configuration: %v", err)
		return status, nil
	}
	status.Configured = configured
	
	if !configured {
		status.Error = "cs-haproxy-bouncer SPOA not found in HAProxy configuration"
		return status, nil
	}
	
	// Check if we can find the bouncer in CrowdSec's bouncer list
	bouncersOutput, err := h.dockerClient.ExecCommand(h.cfg.CrowdsecContainerName, []string{
		"cscli", "bouncers", "list", "-o", "json",
	})
	if err != nil {
		status.Error = fmt.Sprintf("Failed to list CrowdSec bouncers: %v", err)
		return status, nil
	}
	
	// Parse bouncer list to find HAProxy bouncer
	if bouncersOutput != "null" && bouncersOutput != "" && bouncersOutput != "[]" {
		bouncer := h.findHAProxyBouncer(bouncersOutput)
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
			status.Error = "HAProxy bouncer not found in CrowdSec bouncer list"
		}
	} else {
		status.Connected = false
		status.Error = "No bouncers registered with CrowdSec"
	}
	
	return status, nil
}

// ValidateConfiguration validates the cs-haproxy-bouncer SPOA configuration
func (h *HAProxyBouncerManager) ValidateConfiguration(ctx context.Context) error {
	logger.Info("Validating cs-haproxy-bouncer SPOA configuration")
	
	containerName := h.cfg.TraefikContainerName // Reused field for HAProxy container
	
	// Check if HAProxy configuration file exists and is readable
	configContent, err := h.dockerClient.ExecCommand(containerName, []string{
		"cat", "/usr/local/etc/haproxy/haproxy.cfg",
	})
	if err != nil {
		// Try alternative location
		configContent, err = h.dockerClient.ExecCommand(containerName, []string{
			"cat", "/etc/haproxy/haproxy.cfg",
		})
		if err != nil {
			return fmt.Errorf("HAProxy configuration file not found or not readable: %w", err)
		}
	}
	
	// Basic validation - check for required SPOA fields
	requiredFields := []string{"spoe-agent", "spoe-message"}
	for _, field := range requiredFields {
		if !strings.Contains(strings.ToLower(configContent), field) {
			return fmt.Errorf("required SPOA field '%s' not found in HAProxy configuration", field)
		}
	}
	
	// Check if SPOA socket is accessible
	_, err = h.dockerClient.ExecCommand(containerName, []string{
		"ls", "/tmp/spoa.sock",
	})
	if err != nil {
		logger.Warn("SPOA socket not found, bouncer may not be running", "error", err)
	}
	
	// Check LAPI connectivity from CrowdSec side
	_, err = h.dockerClient.ExecCommand(h.cfg.CrowdsecContainerName, []string{
		"cscli", "lapi", "status",
	})
	if err != nil {
		return fmt.Errorf("CrowdSec LAPI is not accessible: %w", err)
	}
	
	logger.Info("cs-haproxy-bouncer SPOA configuration validation passed")
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

// findHAProxyBouncer finds the HAProxy bouncer in the CrowdSec bouncer list
func (h *HAProxyBouncerManager) findHAProxyBouncer(bouncersJSON string) *BouncerInfo {
	// Parse JSON to find HAProxy bouncer
	// Look for bouncer names that contain "haproxy" or have type "haproxy"
	lines := strings.Split(bouncersJSON, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "[" || line == "]" || line == "null" {
			continue
		}
		
		// Remove trailing comma if present
		line = strings.TrimSuffix(line, ",")
		
		// Simple JSON field extraction for bouncer info
		if strings.Contains(strings.ToLower(line), "haproxy") ||
		   strings.Contains(strings.ToLower(line), "spoa") {
			
			// Extract basic info from the JSON line
			bouncer := &BouncerInfo{
				Name:     "haproxy-bouncer",
				Version:  "unknown",
				LastPull: time.Now().Add(-2 * time.Minute), // Default to 2 minutes ago
				Valid:    true,
				Type:     "haproxy",
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

// GetLAPIKey retrieves the LAPI key from the SPOA bouncer configuration
func (h *HAProxyBouncerManager) GetLAPIKey(ctx context.Context) (string, error) {
	logger.Info("Retrieving LAPI key from cs-haproxy-bouncer configuration")
	
	// cs-haproxy-bouncer typically stores its config in a separate file
	// Try common locations for the bouncer configuration
	configLocations := []string{
		"/etc/crowdsec/bouncers/crowdsec-haproxy-bouncer.conf",
		"/usr/local/etc/crowdsec/bouncers/crowdsec-haproxy-bouncer.conf",
		"/opt/crowdsec-haproxy-bouncer/config.yaml",
	}
	
	containerName := h.cfg.TraefikContainerName // Reused field for HAProxy container
	
	var configContent string
	var err error
	
	for _, location := range configLocations {
		configContent, err = h.dockerClient.ExecCommand(containerName, []string{
			"cat", location,
		})
		if err == nil && configContent != "" {
			break
		}
	}
	
	if err != nil || configContent == "" {
		return "", fmt.Errorf("cs-haproxy-bouncer configuration file not found")
	}
	
	// Extract API key from config (format may vary)
	lines := strings.Split(configContent, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "api_key") || strings.HasPrefix(line, "lapi_key") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
			parts = strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}
	
	return "", fmt.Errorf("API key not found in bouncer configuration")
}

// VerifyLAPIConnection verifies that the cs-haproxy-bouncer can connect to CrowdSec LAPI
func (h *HAProxyBouncerManager) VerifyLAPIConnection(ctx context.Context) error {
	logger.Info("Verifying LAPI connection from cs-haproxy-bouncer")
	
	// Check LAPI status from CrowdSec side
	lapiOutput, err := h.dockerClient.ExecCommand(h.cfg.CrowdsecContainerName, []string{
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
	configured, err := h.IsBouncerConfigured(ctx)
	if err != nil {
		return fmt.Errorf("failed to check bouncer configuration: %w", err)
	}
	
	if !configured {
		return fmt.Errorf("cs-haproxy-bouncer SPOA is not configured")
	}
	
	logger.Info("LAPI connection verification successful")
	return nil
}

// GetBouncerConfiguration retrieves the complete bouncer configuration
func (h *HAProxyBouncerManager) GetBouncerConfiguration(ctx context.Context) (map[string]interface{}, error) {
	logger.Info("Retrieving cs-haproxy-bouncer configuration")
	
	containerName := h.cfg.TraefikContainerName // Reused field for HAProxy container
	
	// Read HAProxy config to extract SPOA configuration
	configContent, err := h.dockerClient.ExecCommand(containerName, []string{
		"cat", "/usr/local/etc/haproxy/haproxy.cfg",
	})
	if err != nil {
		// Try alternative location
		configContent, err = h.dockerClient.ExecCommand(containerName, []string{
			"cat", "/etc/haproxy/haproxy.cfg",
		})
		if err != nil {
			return nil, fmt.Errorf("failed to read HAProxy config: %w", err)
		}
	}
	
	// Parse SPOA configuration from HAProxy config
	config := make(map[string]interface{})
	lines := strings.Split(configContent, "\n")
	
	inSPOASection := false
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.HasPrefix(line, "spoe-agent") {
			inSPOASection = true
			config["spoe_agent"] = strings.TrimPrefix(line, "spoe-agent ")
			continue
		}
		
		if inSPOASection {
			if strings.HasPrefix(line, "spoe-message") {
				config["spoe_message"] = strings.TrimPrefix(line, "spoe-message ")
			} else if strings.HasPrefix(line, "option") {
				if options, exists := config["options"]; exists {
					if optSlice, ok := options.([]string); ok {
						config["options"] = append(optSlice, strings.TrimPrefix(line, "option "))
					}
				} else {
					config["options"] = []string{strings.TrimPrefix(line, "option ")}
				}
			} else if line == "" || strings.HasPrefix(line, "#") {
				continue
			} else if !strings.Contains(line, "spoe") {
				inSPOASection = false
			}
		}
	}
	
	return config, nil
}

// CheckSPOASocket checks if the SPOA socket is accessible
func (h *HAProxyBouncerManager) CheckSPOASocket(ctx context.Context) error {
	logger.Info("Checking SPOA socket connectivity")
	
	containerName := h.cfg.TraefikContainerName // Reused field for HAProxy container
	
	// Check if SPOA socket exists and is accessible
	_, err := h.dockerClient.ExecCommand(containerName, []string{
		"ls", "-la", "/tmp/spoa.sock",
	})
	if err != nil {
		return fmt.Errorf("SPOA socket not accessible: %w", err)
	}
	
	// Try to test socket connectivity (basic check)
	_, err = h.dockerClient.ExecCommand(containerName, []string{
		"timeout", "1", "nc", "-U", "/tmp/spoa.sock",
	})
	if err != nil {
		logger.Warn("SPOA socket connectivity test failed", "error", err)
		return fmt.Errorf("SPOA socket not responding: %w", err)
	}
	
	logger.Info("SPOA socket is accessible and responding")
	return nil
}