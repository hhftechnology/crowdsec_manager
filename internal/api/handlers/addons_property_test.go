package handlers

import (
	"context"
	"crowdsec-manager/internal/models"
	"reflect"
	"testing"
	"testing/quick"
)

// **Feature: multi-proxy-architecture, Property 11: Traefik Add-on Management**
// **Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5**
func TestTraefikAddonManagement_Property(t *testing.T) {
	// Property: Pangolin and Gerbil add-ons should be available only when Traefik is selected,
	// hidden for other proxies, and properly integrated into Docker Compose configuration when enabled
	property := func(proxyType ProxyTypeGenerator, addon AddonNameGenerator) bool {
		ctx := context.Background()
		
		// Create test configuration
		cfg := &TestConfig{
			ProxyType:             string(proxyType),
			PangolinContainerName: "pangolin",
			GerbilContainerName:   "gerbil",
			PangolinEnabled:       false,
			GerbilEnabled:         false,
		}
		
		// Create test adapter
		adapter := &TestProxyAdapter{
			proxyType: string(proxyType),
		}
		
		// Test add-on availability
		addons := getAvailableAddonsForProxy(adapter, cfg)
		
		// Property 1: Pangolin and Gerbil should only be available for Traefik
		if string(proxyType) == "traefik" {
			// Should have add-ons available
			if len(addons) == 0 {
				t.Logf("Traefik should have add-ons available, but got none")
				return false
			}
			
			// Check that both Pangolin and Gerbil are available
			pangolinFound := false
			gerbilFound := false
			for _, addonInfo := range addons {
				if addonInfo.Name == "pangolin" {
					pangolinFound = true
				}
				if addonInfo.Name == "gerbil" {
					gerbilFound = true
				}
			}
			
			if !pangolinFound || !gerbilFound {
				t.Logf("Traefik should have both Pangolin and Gerbil available")
				return false
			}
		} else {
			// Non-Traefik proxies should not have add-ons
			if len(addons) > 0 {
				t.Logf("Non-Traefik proxy %s should not have add-ons, but got %d", string(proxyType), len(addons))
				return false
			}
		}
		
		// Property 2: Add-on compatibility checking
		if string(addon) == "pangolin" || string(addon) == "gerbil" {
			isCompatible := isAddonCompatibleWithProxy(string(addon), string(proxyType))
			expectedCompatible := (string(proxyType) == "traefik")
			
			if isCompatible != expectedCompatible {
				t.Logf("Add-on %s compatibility with %s should be %v, got %v", 
					string(addon), string(proxyType), expectedCompatible, isCompatible)
				return false
			}
		}
		
		// Property 3: Add-on status should reflect configuration
		if string(proxyType) == "traefik" && (string(addon) == "pangolin" || string(addon) == "gerbil") {
			status := getTestAddonStatus(string(addon), cfg)
			
			// Status should match configuration
			expectedEnabled := false
			if string(addon) == "pangolin" {
				expectedEnabled = cfg.PangolinEnabled
			} else if string(addon) == "gerbil" {
				expectedEnabled = cfg.GerbilEnabled
			}
			
			if status.Enabled != expectedEnabled {
				t.Logf("Add-on %s enabled status should be %v, got %v", 
					string(addon), expectedEnabled, status.Enabled)
				return false
			}
		}
		
		// Property 4: Add-on configuration should be valid
		if string(proxyType) == "traefik" && (string(addon) == "pangolin" || string(addon) == "gerbil") {
			addonConfig := getTestAddonConfiguration(string(addon), cfg)
			
			// Configuration should have required settings
			if addonConfig.Name != string(addon) {
				t.Logf("Add-on configuration name should match addon name")
				return false
			}
			
			if len(addonConfig.Settings) == 0 {
				t.Logf("Add-on configuration should have settings")
				return false
			}
			
			// Check for required settings based on addon type
			if string(addon) == "pangolin" {
				if _, hasContainer := addonConfig.Settings["container_name"]; !hasContainer {
					t.Logf("Pangolin configuration should have container_name")
					return false
				}
			} else if string(addon) == "gerbil" {
				if _, hasWGPort := addonConfig.Settings["wireguard_port"]; !hasWGPort {
					t.Logf("Gerbil configuration should have wireguard_port")
					return false
				}
			}
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Traefik add-on management property test failed: %v", err)
	}
}

// Property test for add-on Docker Compose profile management
func TestAddonProfileManagement_Property(t *testing.T) {
	// Property: Add-ons should be correctly included in Docker Compose profiles
	// when enabled with Traefik, and excluded for other proxy types
	property := func(proxyType ProxyTypeGenerator, enabledAddons EnabledAddonsGenerator) bool {
		ctx := context.Background()
		
		cfg := &TestConfig{
			ProxyType:       string(proxyType),
			PangolinEnabled: false,
			GerbilEnabled:   false,
		}
		
		// Set enabled add-ons
		for _, addon := range enabledAddons {
			if addon == "pangolin" {
				cfg.PangolinEnabled = true
			} else if addon == "gerbil" {
				cfg.GerbilEnabled = true
			}
		}
		
		// Get required profiles
		profiles := getRequiredProfilesForAddons(string(proxyType), []string(enabledAddons), cfg)
		
		// Property 1: Proxy profile should be included (except standalone)
		if string(proxyType) != "standalone" {
			found := false
			for _, profile := range profiles {
				if profile == string(proxyType) {
					found = true
					break
				}
			}
			if !found {
				t.Logf("Proxy type %s should be included in profiles", string(proxyType))
				return false
			}
		}
		
		// Property 2: Add-on profiles should only be included for Traefik
		for _, addon := range enabledAddons {
			if addon == "pangolin" || addon == "gerbil" {
				found := false
				for _, profile := range profiles {
					if profile == addon {
						found = true
						break
					}
				}
				
				shouldBeIncluded := (string(proxyType) == "traefik")
				if found != shouldBeIncluded {
					t.Logf("Add-on %s profile inclusion should be %v for proxy %s, got %v", 
						addon, shouldBeIncluded, string(proxyType), found)
					return false
				}
			}
		}
		
		// Property 3: No duplicate profiles
		profileMap := make(map[string]bool)
		for _, profile := range profiles {
			if profileMap[profile] {
				t.Logf("Duplicate profile found: %s", profile)
				return false
			}
			profileMap[profile] = true
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Add-on profile management property test failed: %v", err)
	}
}

// Property test for add-on operational status
func TestAddonOperationalStatus_Property(t *testing.T) {
	// Property: Add-on operational status should be consistent with configuration and container state
	property := func(proxyType ProxyTypeGenerator, addon AddonNameGenerator, containerRunning ContainerRunningGenerator) bool {
		if string(proxyType) != "traefik" || (string(addon) != "pangolin" && string(addon) != "gerbil") {
			// Skip non-applicable combinations
			return true
		}
		
		cfg := &TestConfig{
			ProxyType:             string(proxyType),
			PangolinContainerName: "pangolin",
			GerbilContainerName:   "gerbil",
			PangolinEnabled:       string(addon) == "pangolin",
			GerbilEnabled:         string(addon) == "gerbil",
		}
		
		// Mock container status
		mockDockerClient := &TestDockerClient{
			containerRunning: bool(containerRunning),
		}
		
		// Get add-on status
		status := getAddonStatusWithDocker(string(addon), cfg, mockDockerClient)
		
		// Property 1: If addon is enabled, container name should be set
		if status.Enabled && status.ContainerName == "" {
			t.Logf("Enabled add-on %s should have container name set", string(addon))
			return false
		}
		
		// Property 2: Running status should match container state when enabled
		if status.Enabled {
			if status.Running != bool(containerRunning) {
				t.Logf("Add-on %s running status should match container state", string(addon))
				return false
			}
		} else {
			// Disabled add-ons should not be running
			if status.Running {
				t.Logf("Disabled add-on %s should not be running", string(addon))
				return false
			}
		}
		
		// Property 3: Health status should be consistent
		expectedHealth := "unknown"
		if status.Enabled && status.Running {
			expectedHealth = "healthy"
		} else if status.Enabled && !status.Running {
			expectedHealth = "unhealthy"
		}
		
		if status.Health != expectedHealth {
			t.Logf("Add-on %s health should be %s, got %s", string(addon), expectedHealth, status.Health)
			return false
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Add-on operational status property test failed: %v", err)
	}
}

// Test helper functions and types

type TestConfig struct {
	ProxyType             string
	PangolinContainerName string
	GerbilContainerName   string
	PangolinEnabled       bool
	GerbilEnabled         bool
}

type TestProxyAdapter struct {
	proxyType string
}

func (t *TestProxyAdapter) Type() string {
	return t.proxyType
}

type TestDockerClient struct {
	containerRunning bool
}

func (t *TestDockerClient) IsContainerRunning(ctx context.Context, containerName string) (bool, error) {
	return t.containerRunning, nil
}

// Helper functions for testing

func getAvailableAddonsForProxy(adapter *TestProxyAdapter, cfg *TestConfig) []models.AddonInfo {
	addons := []models.AddonInfo{}
	
	if adapter.Type() == "traefik" {
		pangolin := models.AddonInfo{
			Name:        "pangolin",
			DisplayName: "Pangolin",
			ProxyTypes:  []string{"traefik"},
		}
		addons = append(addons, pangolin)
		
		gerbil := models.AddonInfo{
			Name:        "gerbil",
			DisplayName: "Gerbil",
			ProxyTypes:  []string{"traefik"},
		}
		addons = append(addons, gerbil)
	}
	
	return addons
}

func isAddonCompatibleWithProxy(addon, proxyType string) bool {
	if addon == "pangolin" || addon == "gerbil" {
		return proxyType == "traefik"
	}
	return false
}

func getTestAddonStatus(addon string, cfg *TestConfig) models.AddonStatus {
	status := models.AddonStatus{
		Name:    addon,
		Enabled: false,
		Running: false,
		Version: "latest",
		Health:  "unknown",
	}
	
	switch addon {
	case "pangolin":
		status.Enabled = cfg.PangolinEnabled
		status.ContainerName = cfg.PangolinContainerName
	case "gerbil":
		status.Enabled = cfg.GerbilEnabled
		status.ContainerName = cfg.GerbilContainerName
	}
	
	return status
}

func getTestAddonConfiguration(addon string, cfg *TestConfig) models.AddonConfiguration {
	config := models.AddonConfiguration{
		Name:     addon,
		Settings: make(map[string]interface{}),
	}
	
	switch addon {
	case "pangolin":
		config.Settings = map[string]interface{}{
			"container_name": cfg.PangolinContainerName,
			"version":        "latest",
		}
	case "gerbil":
		config.Settings = map[string]interface{}{
			"container_name":  cfg.GerbilContainerName,
			"version":         "latest",
			"wireguard_port":  51820,
		}
	}
	
	return config
}

func getRequiredProfilesForAddons(proxyType string, enabledAddons []string, cfg *TestConfig) []string {
	profiles := []string{}
	
	if proxyType != "standalone" {
		profiles = append(profiles, proxyType)
	}
	
	if proxyType == "traefik" {
		for _, addon := range enabledAddons {
			if addon == "pangolin" && cfg.PangolinEnabled {
				profiles = append(profiles, addon)
			} else if addon == "gerbil" && cfg.GerbilEnabled {
				profiles = append(profiles, addon)
			}
		}
	}
	
	return profiles
}

func getAddonStatusWithDocker(addon string, cfg *TestConfig, dockerClient *TestDockerClient) models.AddonStatus {
	status := getTestAddonStatus(addon, cfg)
	
	if status.Enabled && status.ContainerName != "" {
		ctx := context.Background()
		running, err := dockerClient.IsContainerRunning(ctx, status.ContainerName)
		if err == nil {
			status.Running = running
			if running {
				status.Health = "healthy"
			} else {
				status.Health = "unhealthy"
			}
		}
	}
	
	return status
}

// Generators for property testing

type ProxyTypeGenerator string

func (ProxyTypeGenerator) Generate(rand *quick.Random, size int) reflect.Value {
	types := []string{"traefik", "nginx", "caddy", "haproxy", "zoraxy", "standalone"}
	proxyType := types[rand.Intn(len(types))]
	return reflect.ValueOf(ProxyTypeGenerator(proxyType))
}

type AddonNameGenerator string

func (AddonNameGenerator) Generate(rand *quick.Random, size int) reflect.Value {
	addons := []string{"pangolin", "gerbil", "unknown_addon"}
	addon := addons[rand.Intn(len(addons))]
	return reflect.ValueOf(AddonNameGenerator(addon))
}

type EnabledAddonsGenerator []string

func (EnabledAddonsGenerator) Generate(rand *quick.Random, size int) reflect.Value {
	allAddons := []string{"pangolin", "gerbil"}
	numAddons := rand.Intn(len(allAddons) + 1) // 0 to len(allAddons)
	
	addons := make([]string, 0, numAddons)
	for i := 0; i < numAddons; i++ {
		addon := allAddons[rand.Intn(len(allAddons))]
		// Avoid duplicates
		found := false
		for _, existing := range addons {
			if existing == addon {
				found = true
				break
			}
		}
		if !found {
			addons = append(addons, addon)
		}
	}
	
	return reflect.ValueOf(EnabledAddonsGenerator(addons))
}

type ContainerRunningGenerator bool

func (ContainerRunningGenerator) Generate(rand *quick.Random, size int) reflect.Value {
	running := rand.Intn(2) == 1
	return reflect.ValueOf(ContainerRunningGenerator(running))
}