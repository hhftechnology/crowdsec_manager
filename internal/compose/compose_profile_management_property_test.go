package compose

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
)

// **Feature: multi-proxy-architecture, Property 15: Docker Compose Profile Management**
// **Validates: Requirements 9.5, 10.3, 10.4**
func TestDockerComposeProfileManagement_Property(t *testing.T) {
	// Property: For any proxy profile specification, the system should start only services 
	// relevant to the selected proxy type, include optional components (Pangolin/Gerbil) 
	// only when appropriate, and maintain service isolation
	property := func(proxyType ProfileProxyTypeGenerator, addons ProfileAddonGenerator) bool {
		ctx := context.Background()
		
		// Create temporary directory for test
		tempDir, err := os.MkdirTemp("", "profile_test_*")
		if err != nil {
			t.Logf("Failed to create temp dir: %v", err)
			return false
		}
		defer os.RemoveAll(tempDir)
		
		// Create test compose files
		if err := createProfileTestComposeFiles(tempDir); err != nil {
			t.Logf("Failed to create test files: %v", err)
			return false
		}
		
		manager := NewComposeManager(tempDir, "single", string(proxyType))
		
		// Test profile management
		profiles, err := manager.GetRequiredProfiles(ctx, []string(addons))
		if err != nil {
			t.Logf("Failed to get required profiles: %v", err)
			return false
		}
		
		// Property 1: Only services relevant to selected proxy type should be included
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
		} else {
			// Standalone should not include any proxy profiles
			for _, profile := range profiles {
				if profile == "traefik" || profile == "nginx" || profile == "caddy" || 
				   profile == "haproxy" || profile == "zoraxy" {
					t.Logf("Standalone mode should not include proxy profile: %s", profile)
					return false
				}
			}
		}
		
		// Property 2: Optional components (Pangolin/Gerbil) should only be included when appropriate
		for _, addon := range addons {
			if addon == "pangolin" || addon == "gerbil" {
				addonIncluded := false
				for _, profile := range profiles {
					if profile == addon {
						addonIncluded = true
						break
					}
				}
				
				// These add-ons should only be included with Traefik
				if string(proxyType) == "traefik" {
					if !addonIncluded {
						t.Logf("Add-on %s should be included with Traefik", addon)
						return false
					}
				} else {
					if addonIncluded {
						t.Logf("Add-on %s should not be included with proxy %s", addon, string(proxyType))
						return false
					}
				}
			}
		}
		
		// Property 3: Service isolation - no conflicting proxy profiles
		proxyProfiles := []string{"traefik", "nginx", "caddy", "haproxy", "zoraxy"}
		proxyCount := 0
		for _, profile := range profiles {
			for _, proxyProfile := range proxyProfiles {
				if profile == proxyProfile {
					proxyCount++
				}
			}
		}
		
		// Should have at most one proxy profile (or zero for standalone)
		if string(proxyType) == "standalone" {
			if proxyCount != 0 {
				t.Logf("Standalone mode should have no proxy profiles, got %d", proxyCount)
				return false
			}
		} else {
			if proxyCount != 1 {
				t.Logf("Should have exactly one proxy profile, got %d", proxyCount)
				return false
			}
		}
		
		// Property 4: Profile uniqueness - no duplicate profiles
		profileMap := make(map[string]bool)
		for _, profile := range profiles {
			if profileMap[profile] {
				t.Logf("Duplicate profile found: %s", profile)
				return false
			}
			profileMap[profile] = true
		}
		
		// Property 5: Compose command generation should include correct profiles
		cmd, err := manager.GetComposeCommand(ctx, []string(addons))
		if err != nil {
			t.Logf("Failed to get compose command: %v", err)
			return false
		}
		
		// Verify command structure
		if len(cmd) < 1 || cmd[0] != "docker-compose" {
			t.Logf("Invalid compose command structure: %v", cmd)
			return false
		}
		
		// Count profile flags in command
		profileFlags := 0
		for i := 0; i < len(cmd)-1; i++ {
			if cmd[i] == "--profile" {
				profileFlags++
			}
		}
		
		// Should have correct number of profile flags
		if profileFlags != len(profiles) {
			t.Logf("Profile flags mismatch: expected %d, got %d", len(profiles), profileFlags)
			return false
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Docker Compose profile management property test failed: %v", err)
	}
}

// Property test for addon compatibility
func TestAddonCompatibility_Property(t *testing.T) {
	// Property: Add-ons should only be compatible with appropriate proxy types
	property := func(proxyType ProfileProxyTypeGenerator, addon ProfileSingleAddonGenerator) bool {
		manager := NewComposeManager("/tmp", "single", string(proxyType))
		
		isCompatible := manager.IsAddonCompatible(string(addon))
		
		// Property: Pangolin and Gerbil are only compatible with Traefik
		if string(addon) == "pangolin" || string(addon) == "gerbil" {
			expectedCompatible := string(proxyType) == "traefik"
			if isCompatible != expectedCompatible {
				t.Logf("Add-on %s compatibility with %s: expected %v, got %v", 
					string(addon), string(proxyType), expectedCompatible, isCompatible)
				return false
			}
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Addon compatibility property test failed: %v", err)
	}
}

// Property test for deployment strategy consistency
func TestDeploymentStrategyConsistency_Property(t *testing.T) {
	// Property: Deployment strategy should be consistent with compose mode and proxy type
	property := func(proxyType ProfileProxyTypeGenerator, mode ProfileComposeModeGenerator) bool {
		ctx := context.Background()
		
		// Create temporary directory for test
		tempDir, err := os.MkdirTemp("", "strategy_test_*")
		if err != nil {
			t.Logf("Failed to create temp dir: %v", err)
			return false
		}
		defer os.RemoveAll(tempDir)
		
		// Create test compose files
		if err := createProfileTestComposeFiles(tempDir); err != nil {
			t.Logf("Failed to create test files: %v", err)
			return false
		}
		
		manager := NewComposeManager(tempDir, string(mode), string(proxyType))
		
		strategy, err := manager.GetDeploymentStrategy(ctx)
		if err != nil {
			t.Logf("Failed to get deployment strategy: %v", err)
			return false
		}
		
		// Property: Single mode should use profiles, separate mode should use multiple files
		if string(mode) == "single" {
			if !strategy.UsesProfiles {
				t.Logf("Single mode should use profiles")
				return false
			}
			if len(strategy.ComposeFiles) != 1 {
				t.Logf("Single mode should use one compose file, got %d", len(strategy.ComposeFiles))
				return false
			}
		} else if string(mode) == "separate" {
			if strategy.UsesProfiles {
				t.Logf("Separate mode should not use profiles")
				return false
			}
			expectedFiles := 1 // core file
			if string(proxyType) != "standalone" {
				expectedFiles++ // proxy-specific file
			}
			if len(strategy.ComposeFiles) != expectedFiles {
				t.Logf("Separate mode should use %d compose files, got %d", expectedFiles, len(strategy.ComposeFiles))
				return false
			}
		}
		
		// Property: Proxy-specific files should be included appropriately
		if string(proxyType) != "standalone" && string(mode) == "separate" {
			found := false
			for _, file := range strategy.ComposeFiles {
				if strings.Contains(file, string(proxyType)) {
					found = true
					break
				}
			}
			if !found {
				t.Logf("Separate mode should include proxy-specific file for %s", string(proxyType))
				return false
			}
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Deployment strategy consistency property test failed: %v", err)
	}
}

// Helper function to create test compose files for profile testing
func createProfileTestComposeFiles(dir string) error {
	files := map[string]string{
		"docker-compose.yml": `version: '3.8'
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    profiles: ["crowdsec"]
  
  traefik:
    image: traefik:latest
    profiles: ["traefik"]
  
  nginx:
    image: jc21/nginx-proxy-manager:latest
    profiles: ["nginx"]
  
  caddy:
    image: caddy:latest
    profiles: ["caddy"]
  
  haproxy:
    image: haproxy:latest
    profiles: ["haproxy"]
  
  zoraxy:
    image: zoraxydocker/zoraxy:latest
    profiles: ["zoraxy"]
  
  pangolin:
    image: pangolin:latest
    profiles: ["traefik", "pangolin"]
  
  gerbil:
    image: gerbil:latest
    profiles: ["traefik", "gerbil"]
`,
		"docker-compose.core.yml": `version: '3.8'
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
`,
		"docker-compose.traefik.yml": `version: '3.8'
services:
  traefik:
    image: traefik:latest
`,
		"docker-compose.nginx.yml": `version: '3.8'
services:
  nginx:
    image: jc21/nginx-proxy-manager:latest
`,
		"docker-compose.caddy.yml": `version: '3.8'
services:
  caddy:
    image: caddy:latest
`,
		"docker-compose.haproxy.yml": `version: '3.8'
services:
  haproxy:
    image: haproxy:latest
`,
		"docker-compose.zoraxy.yml": `version: '3.8'
services:
  zoraxy:
    image: zoraxydocker/zoraxy:latest
`,
	}
	
	for filename, content := range files {
		path := filepath.Join(dir, filename)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return err
		}
	}
	
	return nil
}

// Generators for property testing

type ProfileProxyTypeGenerator string

func (ProfileProxyTypeGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	types := []string{"traefik", "nginx", "caddy", "haproxy", "zoraxy", "standalone"}
	proxyType := types[rand.Rand.Intn(len(types))]
	return reflect.ValueOf(ProfileProxyTypeGenerator(proxyType))
}

type ProfileAddonGenerator []string

func (ProfileAddonGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	allAddons := []string{"pangolin", "gerbil"}
	numAddons := rand.Rand.Intn(len(allAddons) + 1) // 0 to len(allAddons)
	
	addons := make([]string, 0, numAddons)
	for i := 0; i < numAddons; i++ {
		addon := allAddons[rand.Rand.Intn(len(allAddons))]
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
	
	return reflect.ValueOf(ProfileAddonGenerator(addons))
}

type ProfileSingleAddonGenerator string

func (ProfileSingleAddonGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	addons := []string{"pangolin", "gerbil"}
	addon := addons[rand.Rand.Intn(len(addons))]
	return reflect.ValueOf(ProfileSingleAddonGenerator(addon))
}

type ProfileComposeModeGenerator string

func (ProfileComposeModeGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	modes := []string{"single", "separate"}
	mode := modes[rand.Rand.Intn(len(modes))]
	return reflect.ValueOf(ProfileComposeModeGenerator(mode))
}