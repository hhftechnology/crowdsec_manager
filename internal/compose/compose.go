package compose

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// ComposeManager handles Docker Compose deployment strategies
type ComposeManager struct {
	WorkDir     string
	ComposeMode string
	ProxyType   string
}

// DeploymentStrategy represents a Docker Compose deployment configuration
type DeploymentStrategy struct {
	UsesProfiles  bool
	ComposeFiles  []string
	RequiredFiles []string
	Profiles      []string
}

// NewComposeManager creates a new compose manager
func NewComposeManager(workDir, composeMode, proxyType string) *ComposeManager {
	return &ComposeManager{
		WorkDir:     workDir,
		ComposeMode: composeMode,
		ProxyType:   proxyType,
	}
}

// GetDeploymentStrategy returns the appropriate deployment strategy based on compose mode
func (c *ComposeManager) GetDeploymentStrategy(ctx context.Context) (*DeploymentStrategy, error) {
	strategy := &DeploymentStrategy{}
	
	switch c.ComposeMode {
	case "single":
		strategy.UsesProfiles = true
		strategy.ComposeFiles = []string{filepath.Join(c.WorkDir, "docker-compose.yml")}
		
		// Add proxy profile if not standalone
		if c.ProxyType != "standalone" {
			strategy.Profiles = []string{c.ProxyType}
		}
		
	case "separate":
		strategy.UsesProfiles = false
		strategy.ComposeFiles = []string{
			filepath.Join(c.WorkDir, "docker-compose.core.yml"),
		}
		
		// Add proxy-specific compose file if not standalone
		if c.ProxyType != "standalone" {
			proxyFile := filepath.Join(c.WorkDir, fmt.Sprintf("docker-compose.%s.yml", c.ProxyType))
			strategy.ComposeFiles = append(strategy.ComposeFiles, proxyFile)
		}
		
	default:
		return nil, fmt.Errorf("unsupported compose mode: %s", c.ComposeMode)
	}
	
	return strategy, nil
}

// ValidateComposeFiles checks if all required compose files exist
func (c *ComposeManager) ValidateComposeFiles(ctx context.Context) (bool, error) {
	strategy, err := c.GetDeploymentStrategy(ctx)
	if err != nil {
		return false, err
	}
	
	for _, file := range strategy.ComposeFiles {
		if !c.FileExists(file) {
			return false, fmt.Errorf("required compose file does not exist: %s", file)
		}
	}
	
	return true, nil
}

// GetRequiredProfiles returns the profiles needed for the current configuration
func (c *ComposeManager) GetRequiredProfiles(ctx context.Context, addons []string) ([]string, error) {
	profiles := []string{}
	
	// Add proxy profile if not standalone
	if c.ProxyType != "standalone" {
		profiles = append(profiles, c.ProxyType)
	}
	
	// Add compatible add-ons
	for _, addon := range addons {
		if c.IsAddonCompatible(addon) {
			profiles = append(profiles, addon)
		}
	}
	
	return profiles, nil
}

// IsAddonCompatible checks if an addon is compatible with the current proxy type
func (c *ComposeManager) IsAddonCompatible(addon string) bool {
	switch addon {
	case "pangolin", "gerbil":
		// These add-ons are only compatible with Traefik
		return c.ProxyType == "traefik"
	default:
		return false
	}
}

// FileExists checks if a file exists at the given path
func (c *ComposeManager) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// GetComposeCommand returns the appropriate docker-compose command for the deployment strategy
func (c *ComposeManager) GetComposeCommand(ctx context.Context, addons []string) ([]string, error) {
	strategy, err := c.GetDeploymentStrategy(ctx)
	if err != nil {
		return nil, err
	}
	
	cmd := []string{"docker-compose"}
	
	if strategy.UsesProfiles {
		// Single file mode with profiles
		profiles, err := c.GetRequiredProfiles(ctx, addons)
		if err != nil {
			return nil, err
		}
		
		for _, profile := range profiles {
			cmd = append(cmd, "--profile", profile)
		}
	} else {
		// Separate file mode with multiple -f flags
		for _, file := range strategy.ComposeFiles {
			cmd = append(cmd, "-f", file)
		}
	}
	
	return cmd, nil
}