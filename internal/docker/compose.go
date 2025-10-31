package docker

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Healthcheck represents the healthcheck configuration for a service
type Healthcheck struct {
	Test     interface{} `yaml:"test,omitempty"`
	Interval string      `yaml:"interval,omitempty"`
	Timeout  string      `yaml:"timeout,omitempty"`
	Retries  int         `yaml:"retries,omitempty"`
	StartPeriod string   `yaml:"start_period,omitempty"`
}

// ComposeService represents a service in docker-compose.yml
type ComposeService struct {
	Image           string                 `yaml:"image,omitempty"`
	ContainerName   string                 `yaml:"container_name,omitempty"`
	Build           map[string]interface{} `yaml:"build,omitempty"`
	Restart         string                 `yaml:"restart,omitempty"`
	Ports           []string               `yaml:"ports,omitempty"`
	Environment     interface{}            `yaml:"environment,omitempty"`
	Volumes         []string               `yaml:"volumes,omitempty"`
	Networks        interface{}            `yaml:"networks,omitempty"`
	DependsOn       interface{}            `yaml:"depends_on,omitempty"`
	Labels          interface{}            `yaml:"labels,omitempty"`
	Command         interface{}            `yaml:"command,omitempty"`
	StopGracePeriod string                 `yaml:"stop_grace_period,omitempty"`
	Healthcheck     *Healthcheck           `yaml:"healthcheck,omitempty"`
	CapAdd          []string               `yaml:"cap_add,omitempty"`
	NetworkMode     string                 `yaml:"network_mode,omitempty"`
}

// ComposeFile represents a docker-compose.yml file structure
type ComposeFile struct {
	Name     string                    `yaml:"name,omitempty"`
	Version  string                    `yaml:"version,omitempty"`
	Services map[string]ComposeService `yaml:"services"`
	Networks map[string]interface{}    `yaml:"networks,omitempty"`
	Volumes  map[string]interface{}    `yaml:"volumes,omitempty"`
}

// LoadComposeFile loads and parses a docker-compose.yml file
func LoadComposeFile(filePath string) (*ComposeFile, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read compose file: %w", err)
	}

	var compose ComposeFile
	if err := yaml.Unmarshal(data, &compose); err != nil {
		return nil, fmt.Errorf("failed to parse compose file: %w", err)
	}

	return &compose, nil
}

// SaveComposeFile saves a ComposeFile structure to a docker-compose.yml file
func SaveComposeFile(filePath string, compose *ComposeFile) error {
	data, err := yaml.Marshal(compose)
	if err != nil {
		return fmt.Errorf("failed to marshal compose file: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write compose file: %w", err)
	}

	return nil
}

// UpdateServiceImage updates the image tag for a specific service
func (c *ComposeFile) UpdateServiceImage(serviceName, imageName, tag string) error {
	service, exists := c.Services[serviceName]
	if !exists {
		return fmt.Errorf("service '%s' not found in compose file", serviceName)
	}

	// Construct the full image reference
	fullImage := imageName + ":" + tag
	service.Image = fullImage

	// Update the service in the map
	c.Services[serviceName] = service

	return nil
}

// GetServiceImage returns the current image for a service
func (c *ComposeFile) GetServiceImage(serviceName string) (string, error) {
	service, exists := c.Services[serviceName]
	if !exists {
		return "", fmt.Errorf("service '%s' not found in compose file", serviceName)
	}

	return service.Image, nil
}

// UpdateComposeFileTags updates multiple service tags in docker-compose.yml
func UpdateComposeFileTags(filePath string, updates map[string]string) error {
	// Load the compose file
	compose, err := LoadComposeFile(filePath)
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

		if err := compose.UpdateServiceImage(serviceName, baseImage, newTag); err != nil {
			return err
		}
	}

	// Save the updated compose file
	if err := SaveComposeFile(filePath, compose); err != nil {
		return err
	}

	return nil
}
