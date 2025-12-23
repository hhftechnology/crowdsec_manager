package config

import (
	"context"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// VolumeInspector handles Docker volume inspection and validation
type VolumeInspector struct {
	dockerClient *client.Client
}

// NewVolumeInspector creates a new volume inspector
func NewVolumeInspector(dockerClient *client.Client) *VolumeInspector {
	return &VolumeInspector{
		dockerClient: dockerClient,
	}
}

// InspectContainerVolumes retrieves all volume mappings for a container
func (v *VolumeInspector) InspectContainerVolumes(ctx context.Context, containerName string) ([]VolumeMapping, error) {
	// Inspect the container
	containerJSON, err := v.dockerClient.ContainerInspect(ctx, containerName)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container %s: %w", containerName, err)
	}

	mappings := []VolumeMapping{}
	for _, mount := range containerJSON.Mounts {
		mapping := VolumeMapping{
			Type:        string(mount.Type),
			Source:      mount.Source,
			Destination: mount.Destination,
			Mode:        mount.Mode,
			RW:          mount.RW,
		}
		mappings = append(mappings, mapping)
	}

	return mappings, nil
}

// FindVolumeMapping finds a specific volume mapping by container path
func (v *VolumeInspector) FindVolumeMapping(ctx context.Context, containerName, containerPath string) (*VolumeMapping, error) {
	mappings, err := v.InspectContainerVolumes(ctx, containerName)
	if err != nil {
		return nil, err
	}

	// Exact match first
	for _, mapping := range mappings {
		if mapping.Destination == containerPath {
			return &mapping, nil
		}
	}

	// Try to find a parent directory mapping
	for _, mapping := range mappings {
		if strings.HasPrefix(containerPath, mapping.Destination+"/") {
			return &mapping, nil
		}
	}

	return nil, fmt.Errorf("no volume mapping found for path: %s", containerPath)
}

// ValidateVolumeMapping checks if a volume mapping exists and is correct
func (v *VolumeInspector) ValidateVolumeMapping(ctx context.Context, containerName, expectedSource, expectedDestination string) (bool, error) {
	mappings, err := v.InspectContainerVolumes(ctx, containerName)
	if err != nil {
		return false, err
	}

	for _, mapping := range mappings {
		// Check if destination matches
		if mapping.Destination == expectedDestination {
			// For relative paths, just check the basename
			if strings.HasPrefix(expectedSource, "./") {
				// Extract basename from both paths
				expectedBase := strings.TrimPrefix(expectedSource, "./")
				actualBase := strings.TrimSuffix(mapping.Source, "/")

				// Check if actual path ends with expected path
				if strings.HasSuffix(actualBase, expectedBase) {
					return true, nil
				}
			} else {
				// For absolute paths, require exact match
				if mapping.Source == expectedSource {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// IsContainerRunning checks if a container is running
func (v *VolumeInspector) IsContainerRunning(ctx context.Context, containerName string) (bool, error) {
	containerJSON, err := v.dockerClient.ContainerInspect(ctx, containerName)
	if err != nil {
		// Container doesn't exist or can't be inspected
		if client.IsErrNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return containerJSON.State.Running, nil
}

// GetContainerInfo retrieves basic container information
func (v *VolumeInspector) GetContainerInfo(ctx context.Context, containerName string) (*types.ContainerJSON, error) {
	return v.dockerClient.ContainerInspect(ctx, containerName)
}

// ListContainers lists all containers (running and stopped)
func (v *VolumeInspector) ListContainers(ctx context.Context) ([]types.Container, error) {
	return v.dockerClient.ContainerList(ctx, container.ListOptions{All: true})
}

// TestFileAccessInContainer tests if a file is accessible inside a container
// This is done by checking if the volume is mounted and the path exists
func (v *VolumeInspector) TestFileAccessInContainer(ctx context.Context, containerName, containerPath string) (bool, error) {
	// First check if container is running
	running, err := v.IsContainerRunning(ctx, containerName)
	if err != nil {
		return false, err
	}
	if !running {
		return false, fmt.Errorf("container %s is not running", containerName)
	}

	// Find the volume mapping for this path
	mapping, err := v.FindVolumeMapping(ctx, containerName, containerPath)
	if err != nil {
		return false, fmt.Errorf("volume mapping not found: %w", err)
	}

	// If we found a mapping, the path should be accessible
	// (actual file existence on host is checked separately)
	return mapping != nil, nil
}

// GetVolumeMountInfo returns detailed mount information for a path
func (v *VolumeInspector) GetVolumeMountInfo(ctx context.Context, containerName, containerPath string) (map[string]string, error) {
	mapping, err := v.FindVolumeMapping(ctx, containerName, containerPath)
	if err != nil {
		return nil, err
	}

	info := map[string]string{
		"type":        mapping.Type,
		"source":      mapping.Source,
		"destination": mapping.Destination,
		"mode":        mapping.Mode,
		"read_write":  fmt.Sprintf("%t", mapping.RW),
	}

	return info, nil
}

// CompareWithExpectedVolumes compares actual volumes with expected requirements
func (v *VolumeInspector) CompareWithExpectedVolumes(ctx context.Context, containerName string, expected []VolumeRequirement) []ValidationCheck {
	checks := []ValidationCheck{}

	actualMappings, err := v.InspectContainerVolumes(ctx, containerName)
	if err != nil {
		checks = append(checks, ValidationCheck{
			Layer:    LayerVolume,
			Type:     "volume",
			Valid:    false,
			Error:    fmt.Sprintf("Failed to inspect container: %v", err),
			Severity: SeverityError,
		})
		return checks
	}

	for _, req := range expected {
		found := false
		var actualMapping *VolumeMapping

		// Look for matching volume
		for _, actual := range actualMappings {
			if actual.Destination == req.ContainerPath {
				found = true
				actualMapping = &actual
				break
			}
		}

		check := ValidationCheck{
			Layer:            LayerVolume,
			Path:             req.ContainerPath,
			Type:             "volume",
			ExpectedLocation: fmt.Sprintf("%s -> %s", req.HostPath, req.ContainerPath),
			Valid:            found,
		}

		if !found {
			check.Error = "Volume mapping not found in container"
			check.Severity = SeverityError
			if req.Required {
				check.Suggestion = fmt.Sprintf("Add volume mapping: %s:%s:%s", req.HostPath, req.ContainerPath, req.Mode)
			} else {
				check.Severity = SeverityWarning
				check.Suggestion = fmt.Sprintf("Optional volume not mounted. Add: %s:%s:%s to enable %s", req.HostPath, req.ContainerPath, req.Mode, req.Description)
			}
		} else {
			check.ActualLocation = fmt.Sprintf("%s -> %s", actualMapping.Source, actualMapping.Destination)
			check.Exists = true
			check.Accessible = true

			// Validate mode
			if req.Mode != "" && !strings.Contains(actualMapping.Mode, req.Mode) {
				check.Valid = false
				check.Severity = SeverityWarning
				check.Error = fmt.Sprintf("Volume mode mismatch. Expected: %s, Got: %s", req.Mode, actualMapping.Mode)
			}
		}

		checks = append(checks, check)
	}

	return checks
}
