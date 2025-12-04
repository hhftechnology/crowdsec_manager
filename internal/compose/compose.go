package compose

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/compose-spec/compose-go/v2/loader"
	"github.com/compose-spec/compose-go/v2/types"
)

// Project wraps the compose-go Project with convenience methods for manipulating compose files
type Project struct {
	*types.Project
	FilePath string
}

// LoadComposeFile parses and validates a docker-compose.yml file with environment variable interpolation
// Skips consistency checks to allow partial compose files
func LoadComposeFile(filePath string) (*Project, error) {
	ctx := context.Background()

	// Get absolute path and working directory
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}
	workDir := filepath.Dir(absPath)

	// Read the compose file content
	content, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read compose file: %w", err)
	}

	// Create config details for the loader
	configDetails := types.ConfigDetails{
		WorkingDir: workDir,
		ConfigFiles: []types.ConfigFile{
			{
				Filename: absPath,
				Content:  content,
			},
		},
		Environment: getEnvironmentMap(),
	}

	// Load and validate the compose file
	project, err := loader.LoadWithContext(ctx, configDetails,
		func(o *loader.Options) {
			o.SetProjectName(getProjectNameFromPath(absPath), false)
			o.SkipConsistencyCheck = true // Allow loading without all referenced files
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load compose file: %w", err)
	}

	return &Project{
		Project:  project,
		FilePath: absPath,
	}, nil
}

// SaveComposeFile serializes and writes the project back to disk as YAML
func SaveComposeFile(filePath string, project *Project) error {
	// Marshal the project to YAML
	data, err := project.MarshalYAML()
	if err != nil {
		return fmt.Errorf("failed to marshal compose file: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write compose file: %w", err)
	}

	return nil
}

// UpdateServiceImage updates the image for a specific service
func (p *Project) UpdateServiceImage(serviceName, imageName, tag string) error {
	fullImage := imageName + ":" + tag

	// Find and update the service
	svc, exists := p.Services[serviceName]
	if !exists {
		return fmt.Errorf("service '%s' not found in compose file", serviceName)
	}

	// Update the image and put the struct back in the map
	svc.Image = fullImage
	p.Services[serviceName] = svc

	return nil
}

// GetServiceImage returns the current image for a service
func (p *Project) GetServiceImage(serviceName string) (string, error) {
	svc, exists := p.Services[serviceName]
	if !exists {
		return "", fmt.Errorf("service '%s' not found in compose file", serviceName)
	}

	return svc.Image, nil
}

// GetService returns a service configuration by name
func (p *Project) GetService(serviceName string) (*types.ServiceConfig, error) {
	svc, exists := p.Services[serviceName]
	if !exists {
		return nil, fmt.Errorf("service '%s' not found in compose file", serviceName)
	}

	return &svc, nil
}

// GetServiceNames returns a list of all service names
func (p *Project) GetServiceNames() []string {
	names := make([]string, 0, len(p.Services))
	for name := range p.Services {
		names = append(names, name)
	}
	return names
}

// GetServiceEnvironment returns the environment variables for a service
func (p *Project) GetServiceEnvironment(serviceName string) (map[string]string, error) {
	svc, err := p.GetService(serviceName)
	if err != nil {
		return nil, err
	}

	env := make(map[string]string)
	for key, value := range svc.Environment {
		if value != nil {
			env[key] = *value
		} else {
			env[key] = ""
		}
	}

	return env, nil
}

// GetServiceVolumes returns the volume configurations for a service
func (p *Project) GetServiceVolumes(serviceName string) ([]types.ServiceVolumeConfig, error) {
	svc, err := p.GetService(serviceName)
	if err != nil {
		return nil, err
	}

	return svc.Volumes, nil
}

// GetServicePorts returns the port configurations for a service
func (p *Project) GetServicePorts(serviceName string) ([]types.ServicePortConfig, error) {
	svc, err := p.GetService(serviceName)
	if err != nil {
		return nil, err
	}

	return svc.Ports, nil
}

// HasService checks if a service exists in the compose file
func (p *Project) HasService(serviceName string) bool {
	_, exists := p.Services[serviceName]
	return exists
}

// GetServiceDependencies returns the services that a service depends on
func (p *Project) GetServiceDependencies(serviceName string) ([]string, error) {
	svc, err := p.GetService(serviceName)
	if err != nil {
		return nil, err
	}

	deps := make([]string, 0, len(svc.DependsOn))
	for depName := range svc.DependsOn {
		deps = append(deps, depName)
	}

	return deps, nil
}

// UpdateComposeFileTags atomically updates multiple service image tags in docker-compose.yml
// Used for updating Pangolin, Gerbil, Traefik, and CrowdSec images
func UpdateComposeFileTags(filePath string, updates map[string]string) error {
	// Load the compose file
	project, err := LoadComposeFile(filePath)
	if err != nil {
		return err
	}

	// Map of service name to base image name
	serviceImages := map[string]string{
		"pangolin": "fosrl/pangolin",
		"gerbil":   "fosrl/gerbil",
		"traefik":  "traefik",
		"crowdsec": "crowdsecurity/crowdsec",
	}

	// Update each service that has a new tag
	for serviceName, newTag := range updates {
		if newTag == "" {
			continue // Skip empty tags
		}

		baseImage, exists := serviceImages[serviceName]
		if !exists {
			return fmt.Errorf("unknown service: %s", serviceName)
		}

		if err := project.UpdateServiceImage(serviceName, baseImage, newTag); err != nil {
			return err
		}
	}

	// Save the updated compose file
	if err := SaveComposeFile(filePath, project); err != nil {
		return err
	}

	return nil
}

// ValidateComposeFile validates a docker-compose.yml file without loading it fully
func ValidateComposeFile(filePath string) error {
	_, err := LoadComposeFile(filePath)
	return err
}

// getEnvironmentMap returns current environment variables as a map
func getEnvironmentMap() map[string]string {
	env := make(map[string]string)
	for _, e := range os.Environ() {
		pair := strings.SplitN(e, "=", 2)
		if len(pair) == 2 {
			env[pair[0]] = pair[1]
		}
	}
	return env
}

// getProjectNameFromPath extracts a project name from the file path
func getProjectNameFromPath(filePath string) string {
	dir := filepath.Dir(filePath)
	return filepath.Base(dir)
}

// GetNetworkNames returns a list of all network names defined in the compose file
func (p *Project) GetNetworkNames() []string {
	names := make([]string, 0, len(p.Networks))
	for name := range p.Networks {
		names = append(names, name)
	}
	return names
}

// GetVolumeNames returns a list of all volume names defined in the compose file
func (p *Project) GetVolumeNames() []string {
	names := make([]string, 0, len(p.Volumes))
	for name := range p.Volumes {
		names = append(names, name)
	}
	return names
}

// GetServiceHealthcheck returns the healthcheck configuration for a service
func (p *Project) GetServiceHealthcheck(serviceName string) (*types.HealthCheckConfig, error) {
	svc, err := p.GetService(serviceName)
	if err != nil {
		return nil, err
	}

	return svc.HealthCheck, nil
}

// GetServiceLabels returns the labels for a service
func (p *Project) GetServiceLabels(serviceName string) (map[string]string, error) {
	svc, err := p.GetService(serviceName)
	if err != nil {
		return nil, err
	}

	labels := make(map[string]string)
	for key, value := range svc.Labels {
		labels[key] = value
	}

	return labels, nil
}

// SetServiceEnvironmentVar sets or updates an environment variable for a service
func (p *Project) SetServiceEnvironmentVar(serviceName, key, value string) error {
	svc, exists := p.Services[serviceName]
	if !exists {
		return fmt.Errorf("service '%s' not found in compose file", serviceName)
	}

	if svc.Environment == nil {
		svc.Environment = make(types.MappingWithEquals)
	}
	svc.Environment[key] = &value
	p.Services[serviceName] = svc

	return nil
}

// GetRawProject returns the underlying compose-go Project for advanced operations
func (p *Project) GetRawProject() *types.Project {
	return p.Project
}
