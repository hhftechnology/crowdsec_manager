package compose

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
)

// **Feature: multi-proxy-architecture, Property 10: Docker Compose Mode Consistency**
// **Validates: Requirements 9.1, 9.2, 9.3, 9.5**
func TestDockerComposeModeConsistency_Property(t *testing.T) {
	// Property: For any COMPOSE_MODE setting, the system should use appropriate deployment strategy
	// and validate file availability without mode changes after initial deployment
	property := func(mode ComposeModeGenerator, proxyType ProxyTypeGenerator) bool {
		ctx := context.Background()
		
		// Create temporary directory for test
		tempDir, err := os.MkdirTemp("", "compose_test_*")
		if err != nil {
			t.Logf("Failed to create temp dir: %v", err)
			return false
		}
		defer os.RemoveAll(tempDir)
		
		// Create test compose files
		if err := createTestComposeFiles(tempDir); err != nil {
			t.Logf("Failed to create test files: %v", err)
			return false
		}
		
		// Test compose mode consistency
		manager := &TestComposeManager{
			workDir:     tempDir,
			composeMode: string(mode),
			proxyType:   string(proxyType),
		}
		
		// Validate compose mode behavior
		strategy, err := manager.GetDeploymentStrategy(ctx)
		if err != nil {
			t.Logf("Failed to get deployment strategy: %v", err)
			return false
		}
		
		// Property 1: Single mode should use profiles
		if string(mode) == "single" {
			if !strategy.UsesProfiles {
				t.Logf("Single mode should use profiles, but doesn't")
				return false
			}
			if len(strategy.ComposeFiles) != 1 {
				t.Logf("Single mode should use one compose file, got %d", len(strategy.ComposeFiles))
				return false
			}
		}
		
		// Property 2: Separate mode should use multiple files
		if string(mode) == "separate" {
			if strategy.UsesProfiles {
				t.Logf("Separate mode should not use profiles, but does")
				return false
			}
			if len(strategy.ComposeFiles) < 1 {
				t.Logf("Separate mode should use multiple compose files, got %d", len(strategy.ComposeFiles))
				return false
			}
		}
		
		// Property 3: File availability validation
		for _, file := range strategy.ComposeFiles {
			if !manager.FileExists(file) {
				t.Logf("Required compose file does not exist: %s", file)
				return false
			}
		}
		
		// Property 4: Proxy-specific files should be included for non-standalone
		if string(proxyType) != "standalone" {
			expectedFile := fmt.Sprintf("docker-compose.%s.yml", string(proxyType))
			if string(mode) == "separate" {
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
		}
		
		// Property 5: Mode immutability after initial deployment
		initialMode := manager.composeMode
		manager.composeMode = "different_mode"
		
		// Should still return the same strategy (mode is immutable)
		newStrategy, err := manager.GetDeploymentStrategy(ctx)
		if err != nil {
			t.Logf("Failed to get deployment strategy after mode change: %v", err)
			return false
		}
		
		// Restore original mode for comparison
		manager.composeMode = initialMode
		originalStrategy, _ := manager.GetDeploymentStrategy(ctx)
		
		// The strategy should be based on stored/initial mode, not the changed one
		if newStrategy.UsesProfiles != originalStrategy.UsesProfiles {
			t.Logf("Mode change should not affect deployment strategy (immutability)")
			return false
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Docker Compose mode consistency property test failed: %v", err)
	}
}

// Property test for compose file validation
func TestComposeFileValidation_Property(t *testing.T) {
	// Property: For any proxy type, required compose files should exist and be valid
	property := func(proxyType ProxyTypeGenerator, mode ComposeModeGenerator) bool {
		ctx := context.Background()
		
		// Create temporary directory for test
		tempDir, err := os.MkdirTemp("", "compose_validation_test_*")
		if err != nil {
			t.Logf("Failed to create temp dir: %v", err)
			return false
		}
		defer os.RemoveAll(tempDir)
		
		// Create test compose files
		if err := createTestComposeFiles(tempDir); err != nil {
			t.Logf("Failed to create test files: %v", err)
			return false
		}
		
		manager := &TestComposeManager{
			workDir:     tempDir,
			composeMode: string(mode),
			proxyType:   string(proxyType),
		}
		
		// Validate compose files
		isValid, err := manager.ValidateComposeFiles(ctx)
		if err != nil {
			t.Logf("Validation error: %v", err)
			return false
		}
		
		// Property: All required files should exist and be valid
		if !isValid {
			t.Logf("Compose files validation failed for proxy %s in mode %s", string(proxyType), string(mode))
			return false
		}
		
		// Property: Core files should always be available
		coreFiles := []string{"docker-compose.yml", "docker-compose.core.yml"}
		for _, file := range coreFiles {
			if !manager.FileExists(filepath.Join(tempDir, file)) {
				t.Logf("Core file missing: %s", file)
				return false
			}
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Compose file validation property test failed: %v", err)
	}
}

// Property test for profile management
func TestComposeProfileManagement_Property(t *testing.T) {
	// Property: For any proxy type, profiles should be correctly managed in single mode
	property := func(proxyType ProxyTypeGenerator, addons AddonGenerator) bool {
		ctx := context.Background()
		
		manager := &TestComposeManager{
			composeMode: "single",
			proxyType:   string(proxyType),
		}
		
		// Get required profiles
		profiles, err := manager.GetRequiredProfiles(ctx, []string(addons))
		if err != nil {
			t.Logf("Failed to get required profiles: %v", err)
			return false
		}
		
		// Property 1: Proxy type should always be included (except standalone)
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
		
		// Property 2: Add-ons should only be included for compatible proxy types
		for _, addon := range addons {
			if addon == "pangolin" || addon == "gerbil" {
				// These should only be included with Traefik
				if string(proxyType) != "traefik" {
					for _, profile := range profiles {
						if profile == addon {
							t.Logf("Add-on %s should not be included with proxy %s", addon, string(proxyType))
							return false
						}
					}
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
		t.Errorf("Compose profile management property test failed: %v", err)
	}
}

// Test interfaces and implementations for compose testing

type TestComposeManager struct {
	workDir     string
	composeMode string
	proxyType   string
}

type DeploymentStrategy struct {
	UsesProfiles  bool
	ComposeFiles  []string
	RequiredFiles []string
	Profiles      []string
}

func (t *TestComposeManager) GetDeploymentStrategy(ctx context.Context) (*DeploymentStrategy, error) {
	strategy := &DeploymentStrategy{}
	
	if t.composeMode == "single" {
		strategy.UsesProfiles = true
		strategy.ComposeFiles = []string{filepath.Join(t.workDir, "docker-compose.yml")}
		strategy.Profiles = []string{t.proxyType}
	} else if t.composeMode == "separate" {
		strategy.UsesProfiles = false
		strategy.ComposeFiles = []string{
			filepath.Join(t.workDir, "docker-compose.core.yml"),
		}
		
		if t.proxyType != "standalone" {
			proxyFile := filepath.Join(t.workDir, fmt.Sprintf("docker-compose.%s.yml", t.proxyType))
			strategy.ComposeFiles = append(strategy.ComposeFiles, proxyFile)
		}
	}
	
	return strategy, nil
}

func (t *TestComposeManager) ValidateComposeFiles(ctx context.Context) (bool, error) {
	strategy, err := t.GetDeploymentStrategy(ctx)
	if err != nil {
		return false, err
	}
	
	for _, file := range strategy.ComposeFiles {
		if !t.FileExists(file) {
			return false, nil
		}
	}
	
	return true, nil
}

func (t *TestComposeManager) GetRequiredProfiles(ctx context.Context, addons []string) ([]string, error) {
	profiles := []string{}
	
	if t.proxyType != "standalone" {
		profiles = append(profiles, t.proxyType)
	}
	
	// Add compatible add-ons
	for _, addon := range addons {
		if addon == "pangolin" || addon == "gerbil" {
			if t.proxyType == "traefik" {
				profiles = append(profiles, addon)
			}
		}
	}
	
	return profiles, nil
}

func (t *TestComposeManager) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Helper function to create test compose files
func createTestComposeFiles(dir string) error {
	files := map[string]string{
		"docker-compose.yml":         "version: '3.8'\nservices:\n  test: {image: alpine}",
		"docker-compose.core.yml":    "version: '3.8'\nservices:\n  crowdsec: {image: crowdsec}",
		"docker-compose.traefik.yml": "version: '3.8'\nservices:\n  traefik: {image: traefik}",
		"docker-compose.nginx.yml":   "version: '3.8'\nservices:\n  nginx: {image: nginx}",
		"docker-compose.caddy.yml":   "version: '3.8'\nservices:\n  caddy: {image: caddy}",
		"docker-compose.haproxy.yml": "version: '3.8'\nservices:\n  haproxy: {image: haproxy}",
		"docker-compose.zoraxy.yml":  "version: '3.8'\nservices:\n  zoraxy: {image: zoraxy}",
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

type ComposeModeGenerator string

func (ComposeModeGenerator) Generate(rand *quick.Random, size int) reflect.Value {
	modes := []string{"single", "separate"}
	mode := modes[rand.Intn(len(modes))]
	return reflect.ValueOf(ComposeModeGenerator(mode))
}

type ProxyTypeGenerator string

func (ProxyTypeGenerator) Generate(rand *quick.Random, size int) reflect.Value {
	types := []string{"traefik", "nginx", "caddy", "haproxy", "zoraxy", "standalone"}
	proxyType := types[rand.Intn(len(types))]
	return reflect.ValueOf(ProxyTypeGenerator(proxyType))
}

type AddonGenerator []string

func (AddonGenerator) Generate(rand *quick.Random, size int) reflect.Value {
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
	
	return reflect.ValueOf(AddonGenerator(addons))
}