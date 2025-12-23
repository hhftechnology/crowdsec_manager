package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/client"
)

// Validator handles complete configuration validation
type Validator struct {
	config          *Config
	volumeInspector *VolumeInspector
	ctx             context.Context
}

// NewValidator creates a new configuration validator
func NewValidator(cfg *Config, dockerClient *client.Client) *Validator {
	return &Validator{
		config:          cfg,
		volumeInspector: NewVolumeInspector(dockerClient),
		ctx:             context.Background(),
	}
}

// ValidateComplete performs complete validation of all layers
func (v *Validator) ValidateComplete() (*ValidationResult, error) {
	result := &ValidationResult{
		ProxyType: v.config.ProxyType,
		Timestamp: time.Now(),
		Summary:   ValidationSummary{},
		EnvVars:   EnvVarValidation{},
		Layers:    LayerValidations{},
		Suggestions: []Suggestion{},
		Errors:    []ValidationError{},
		Warnings:  []ValidationWarning{},
	}

	// 1. Validate environment variables
	envVarResult := v.ValidateEnvironmentVariables()
	result.EnvVars = envVarResult

	// 2. Validate host paths (Layer 1)
	hostPathsResult := v.ValidateHostPaths()
	result.Layers.HostPaths = hostPathsResult

	// 3. Validate volume mappings (Layer 2)
	volumeMappingsResult := v.ValidateVolumeMappings()
	result.Layers.VolumeMappings = volumeMappingsResult

	// 4. Validate container paths (Layer 3)
	containerPathsResult := v.ValidateContainerPaths()
	result.Layers.ContainerPaths = containerPathsResult

	// 5. Calculate summary
	result.Summary = v.calculateSummary(result)

	// 6. Generate suggestions based on errors and warnings
	result.Suggestions = v.generateSuggestions(result)

	// 7. Set overall validity
	result.Valid = result.Summary.OverallStatus == StatusValid

	return result, nil
}

// ValidateEnvironmentVariables validates all environment variables for the proxy type
func (v *Validator) ValidateEnvironmentVariables() EnvVarValidation {
	requirements := GetProxyRequirements(v.config.ProxyType)
	validation := EnvVarValidation{
		Required: []EnvVarCheck{},
		Optional: []EnvVarCheck{},
		All:      []EnvVarCheck{},
	}

	// Validate required env vars
	for _, envVar := range requirements.RequiredEnvVars {
		check := v.validateEnvVar(envVar, true)
		validation.Required = append(validation.Required, check)
		validation.All = append(validation.All, check)
	}

	// Validate optional env vars
	for _, envVar := range requirements.OptionalEnvVars {
		check := v.validateEnvVar(envVar, false)
		validation.Optional = append(validation.Optional, check)
		validation.All = append(validation.All, check)
	}

	return validation
}

// validateEnvVar validates a single environment variable
func (v *Validator) validateEnvVar(envVar string, required bool) EnvVarCheck {
	value := os.Getenv(envVar)
	check := EnvVarCheck{
		Name:        envVar,
		Value:       value,
		Required:    required,
		Set:         value != "",
		Description: GetEnvVarDescription(envVar),
		Impact:      GetEnvVarImpact(envVar, v.config.ProxyType),
	}

	// Check if set
	if !check.Set {
		if required {
			check.Valid = false
			check.Severity = SeverityError
			check.Error = "Required environment variable not set"
			check.Suggestion = v.getDefaultEnvVarSuggestion(envVar)
		} else {
			check.Valid = true
			check.Severity = SeverityInfo
			check.Suggestion = v.getDefaultEnvVarSuggestion(envVar)
		}
		return check
	}

	// Validate format based on variable type
	check.Valid = v.validateEnvVarFormat(envVar, value)
	if !check.Valid {
		check.Severity = SeverityError
		check.Error = "Invalid format"
		check.Suggestion = v.getFormatSuggestion(envVar, value)
	} else {
		check.Severity = SeverityInfo
	}

	return check
}

// validateEnvVarFormat validates the format of an environment variable value
func (v *Validator) validateEnvVarFormat(envVar, value string) bool {
	// Container names
	if strings.HasSuffix(envVar, "_CONTAINER_NAME") {
		// Must be valid Docker container name
		matched, _ := regexp.MatchString(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`, value)
		return matched && len(value) <= 255
	}

	// Ports
	if strings.HasSuffix(envVar, "_PORT") {
		port, err := strconv.Atoi(value)
		return err == nil && port > 0 && port <= 65535
	}

	// Paths
	if strings.Contains(envVar, "_PATH") || strings.Contains(envVar, "_CONFIG") || strings.Contains(envVar, "_LOG") || strings.Contains(envVar, "_DIR") {
		// Should be absolute path (starting with /)
		if !strings.HasPrefix(value, "/") {
			return false
		}
		// No trailing slash (except root)
		if value != "/" && strings.HasSuffix(value, "/") {
			return false
		}
		return true
	}

	// Booleans
	if envVar == "PROXY_ENABLED" || strings.HasPrefix(envVar, "INCLUDE_") || strings.Contains(envVar, "_INSECURE") {
		lower := strings.ToLower(value)
		return lower == "true" || lower == "false" || value == "1" || value == "0"
	}

	// Default: valid
	return true
}

// getDefaultEnvVarSuggestion returns a default value suggestion for an env var
func (v *Validator) getDefaultEnvVarSuggestion(envVar string) string {
	requirements := GetProxyRequirements(v.config.ProxyType)

	// Check if it's a path requirement
	for _, pathReq := range requirements.RequiredPaths {
		if pathReq.EnvVar == envVar {
			return fmt.Sprintf("Set to: %s=%s", envVar, pathReq.DefaultPath)
		}
	}
	for _, pathReq := range requirements.OptionalPaths {
		if pathReq.EnvVar == envVar {
			return fmt.Sprintf("Set to: %s=%s", envVar, pathReq.DefaultPath)
		}
	}

	// Container names
	if strings.HasSuffix(envVar, "_CONTAINER_NAME") {
		containerName := strings.ToLower(strings.TrimSuffix(envVar, "_CONTAINER_NAME"))
		if containerName == "npm" {
			return fmt.Sprintf("Set to: %s=nginx-proxy-manager", envVar)
		}
		return fmt.Sprintf("Set to: %s=%s", envVar, containerName)
	}

	return fmt.Sprintf("Set environment variable: %s=<value>", envVar)
}

// getFormatSuggestion returns a suggestion to fix format issues
func (v *Validator) getFormatSuggestion(envVar, value string) string {
	// Path issues
	if strings.Contains(envVar, "_PATH") || strings.Contains(envVar, "_CONFIG") || strings.Contains(envVar, "_LOG") || strings.Contains(envVar, "_DIR") {
		if !strings.HasPrefix(value, "/") {
			return fmt.Sprintf("Path must be absolute. Change to: %s=/%s", envVar, strings.TrimPrefix(value, "./"))
		}
		if strings.HasSuffix(value, "/") && value != "/" {
			return fmt.Sprintf("Remove trailing slash: %s=%s", envVar, strings.TrimSuffix(value, "/"))
		}
	}

	// Container name issues
	if strings.HasSuffix(envVar, "_CONTAINER_NAME") {
		cleaned := regexp.MustCompile(`[^a-zA-Z0-9_.-]`).ReplaceAllString(value, "-")
		return fmt.Sprintf("Use valid container name: %s=%s", envVar, cleaned)
	}

	return fmt.Sprintf("Fix format for: %s", envVar)
}

// ValidateHostPaths validates that required files/directories exist on host
func (v *Validator) ValidateHostPaths() LayerValidation {
	requirements := GetProxyRequirements(v.config.ProxyType)
	checks := []ValidationCheck{}

	// Validate required paths
	for _, pathReq := range requirements.RequiredPaths {
		check := v.validateHostPath(pathReq, true)
		checks = append(checks, check)
	}

	// Validate optional paths
	for _, pathReq := range requirements.OptionalPaths {
		check := v.validateHostPath(pathReq, false)
		checks = append(checks, check)
	}

	return LayerValidation{
		Status: v.determineLayerStatus(checks),
		Checks: checks,
	}
}

// validateHostPath validates a single host path
func (v *Validator) validateHostPath(pathReq PathRequirement, required bool) ValidationCheck {
	check := ValidationCheck{
		Layer:            LayerHost,
		Path:             pathReq.HostPath,
		Type:             pathReq.Type,
		ExpectedLocation: pathReq.HostPath,
	}

	// Check if path exists
	info, err := os.Stat(pathReq.HostPath)
	if err != nil {
		check.Exists = false
		check.Accessible = false
		check.Valid = false

		if required {
			check.Severity = SeverityError
			check.Error = fmt.Sprintf("%s does not exist on host filesystem", pathReq.Type)
			if pathReq.Type == "file" {
				check.Suggestion = fmt.Sprintf("Create file: mkdir -p %s && touch %s", filepath.Dir(pathReq.HostPath), pathReq.HostPath)
			} else {
				check.Suggestion = fmt.Sprintf("Create directory: mkdir -p %s", pathReq.HostPath)
			}
		} else {
			check.Severity = SeverityWarning
			check.Error = fmt.Sprintf("Optional %s not found", pathReq.Type)
			check.Suggestion = fmt.Sprintf("Feature '%s' requires this path. Create with: mkdir -p %s", pathReq.FeatureNeeded, filepath.Dir(pathReq.HostPath))
		}
		return check
	}

	check.Exists = true
	check.ActualLocation = pathReq.HostPath

	// Validate type matches
	if pathReq.Type == "directory" && !info.IsDir() {
		check.Valid = false
		check.Severity = SeverityError
		check.Error = "Expected directory but found file"
		check.Suggestion = fmt.Sprintf("Remove file and create directory: rm %s && mkdir -p %s", pathReq.HostPath, pathReq.HostPath)
		return check
	}

	if pathReq.Type == "file" && info.IsDir() {
		check.Valid = false
		check.Severity = SeverityError
		check.Error = "Expected file but found directory"
		check.Suggestion = fmt.Sprintf("Remove directory and create file: rm -r %s && touch %s", pathReq.HostPath, pathReq.HostPath)
		return check
	}

	// Check if readable
	file, err := os.Open(pathReq.HostPath)
	if err != nil {
		check.Accessible = false
		check.Valid = false
		check.Severity = SeverityError
		check.Error = "Path exists but is not accessible"
		check.Suggestion = fmt.Sprintf("Fix permissions: chmod 644 %s", pathReq.HostPath)
		return check
	}
	file.Close()

	check.Accessible = true
	check.Valid = true
	check.Severity = SeverityInfo

	return check
}

// ValidateVolumeMappings validates Docker volume mappings
func (v *Validator) ValidateVolumeMappings() LayerValidation {
	requirements := GetProxyRequirements(v.config.ProxyType)
	containerName := v.getContainerName()

	checks := v.volumeInspector.CompareWithExpectedVolumes(v.ctx, containerName, requirements.RequiredVolumes)

	return LayerValidation{
		Status: v.determineLayerStatus(checks),
		Checks: checks,
	}
}

// ValidateContainerPaths validates paths inside containers
func (v *Validator) ValidateContainerPaths() LayerValidation {
	requirements := GetProxyRequirements(v.config.ProxyType)
	containerName := v.getContainerName()
	checks := []ValidationCheck{}

	// Check if container is running first
	running, err := v.volumeInspector.IsContainerRunning(v.ctx, containerName)
	if err != nil || !running {
		check := ValidationCheck{
			Layer:    LayerContainer,
			Path:     containerName,
			Type:     "container",
			Valid:    false,
			Severity: SeverityError,
		}
		if err != nil {
			check.Error = fmt.Sprintf("Failed to check container status: %v", err)
		} else {
			check.Error = "Container is not running"
			check.Suggestion = fmt.Sprintf("Start container: docker-compose up -d %s", v.config.ProxyType)
		}
		checks = append(checks, check)
		return LayerValidation{
			Status: StatusError,
			Checks: checks,
		}
	}

	// Validate each required path
	for _, pathReq := range requirements.RequiredPaths {
		check := v.validateContainerPath(containerName, pathReq, true)
		checks = append(checks, check)
	}

	// Validate optional paths
	for _, pathReq := range requirements.OptionalPaths {
		check := v.validateContainerPath(containerName, pathReq, false)
		checks = append(checks, check)
	}

	return LayerValidation{
		Status: v.determineLayerStatus(checks),
		Checks: checks,
	}
}

// validateContainerPath validates a path inside a container
func (v *Validator) validateContainerPath(containerName string, pathReq PathRequirement, required bool) ValidationCheck {
	check := ValidationCheck{
		Layer:            LayerContainer,
		Path:             pathReq.ContainerPath,
		Type:             pathReq.Type,
		ExpectedLocation: pathReq.ContainerPath,
	}

	// Try to access the path
	accessible, err := v.volumeInspector.TestFileAccessInContainer(v.ctx, containerName, pathReq.ContainerPath)
	if err != nil || !accessible {
		check.Exists = false
		check.Accessible = false
		check.Valid = false

		if required {
			check.Severity = SeverityError
			check.Error = "Path not accessible from container"
			check.Suggestion = "Verify volume mapping in docker-compose.yml"
		} else {
			check.Severity = SeverityWarning
			check.Error = "Optional path not accessible"
			check.Suggestion = fmt.Sprintf("Feature '%s' may not work without this path", pathReq.FeatureNeeded)
		}
		return check
	}

	check.Exists = true
	check.Accessible = true
	check.ActualLocation = pathReq.ContainerPath
	check.Valid = true
	check.Severity = SeverityInfo

	return check
}

// getContainerName returns the container name for the current proxy type
func (v *Validator) getContainerName() string {
	switch v.config.ProxyType {
	case "traefik":
		return v.config.TraefikContainerName
	case "nginx":
		return os.Getenv("NPM_CONTAINER_NAME")
	case "caddy":
		return os.Getenv("CADDY_CONTAINER_NAME")
	case "haproxy":
		return os.Getenv("HAPROXY_CONTAINER_NAME")
	case "zoraxy":
		return os.Getenv("ZORAXY_CONTAINER_NAME")
	default:
		return v.config.CrowdsecContainerName
	}
}

// determineLayerStatus determines overall status for a layer based on checks
func (v *Validator) determineLayerStatus(checks []ValidationCheck) ValidationStatus {
	hasError := false
	hasWarning := false

	for _, check := range checks {
		if check.Severity == SeverityError {
			hasError = true
		} else if check.Severity == SeverityWarning {
			hasWarning = true
		}
	}

	if hasError {
		return StatusError
	}
	if hasWarning {
		return StatusWarning
	}
	return StatusValid
}

// calculateSummary calculates the validation summary
func (v *Validator) calculateSummary(result *ValidationResult) ValidationSummary {
	summary := ValidationSummary{}

	// Count checks
	allChecks := append(result.Layers.HostPaths.Checks, result.Layers.VolumeMappings.Checks...)
	allChecks = append(allChecks, result.Layers.ContainerPaths.Checks...)
	allChecks = append(allChecks, v.checksFromEnvVars(result.EnvVars)...)

	summary.TotalChecks = len(allChecks)

	for _, check := range allChecks {
		if check.Valid {
			summary.PassedChecks++
		} else if check.Severity == SeverityError {
			summary.FailedChecks++
		} else if check.Severity == SeverityWarning {
			summary.WarningChecks++
		}
	}

	// Determine overall status
	if summary.FailedChecks > 0 {
		summary.OverallStatus = StatusError
		summary.ReadyToDeploy = false
	} else if summary.WarningChecks > 0 {
		summary.OverallStatus = StatusWarning
		summary.ReadyToDeploy = true
	} else {
		summary.OverallStatus = StatusValid
		summary.ReadyToDeploy = true
	}

	return summary
}

// checksFromEnvVars converts env var checks to validation checks
func (v *Validator) checksFromEnvVars(envVars EnvVarValidation) []ValidationCheck {
	checks := []ValidationCheck{}
	for _, envCheck := range envVars.All {
		checks = append(checks, ValidationCheck{
			Layer:    "env",
			Path:     envCheck.Name,
			Type:     "env_var",
			Valid:    envCheck.Valid,
			Severity: envCheck.Severity,
		})
	}
	return checks
}

// generateSuggestions generates actionable suggestions based on validation results
func (v *Validator) generateSuggestions(result *ValidationResult) []Suggestion {
	engine := NewSuggestionEngine(v.config.ProxyType)
	return engine.GenerateSuggestions(result)
}
