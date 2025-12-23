package config

import (
	"fmt"
	"path/filepath"
	"strings"
)

// SuggestionEngine generates actionable suggestions from validation results
type SuggestionEngine struct {
	proxyType string
}

// NewSuggestionEngine creates a new suggestion engine
func NewSuggestionEngine(proxyType string) *SuggestionEngine {
	return &SuggestionEngine{
		proxyType: proxyType,
	}
}

// GenerateSuggestions analyzes validation results and generates suggestions
func (s *SuggestionEngine) GenerateSuggestions(result *ValidationResult) []Suggestion {
	suggestions := []Suggestion{}
	suggestionID := 1

	// Generate suggestions from env var validation
	suggestions = append(suggestions, s.suggestionsFromEnvVars(result.EnvVars, &suggestionID)...)

	// Generate suggestions from host path validation
	suggestions = append(suggestions, s.suggestionsFromHostPaths(result.Layers.HostPaths, &suggestionID)...)

	// Generate suggestions from volume mapping validation
	suggestions = append(suggestions, s.suggestionsFromVolumeMappings(result.Layers.VolumeMappings, &suggestionID)...)

	// Generate suggestions from container path validation
	suggestions = append(suggestions, s.suggestionsFromContainerPaths(result.Layers.ContainerPaths, &suggestionID)...)

	// Generate optimization suggestions
	suggestions = append(suggestions, s.suggestOptimizations(result, &suggestionID)...)

	return suggestions
}

// suggestionsFromEnvVars generates suggestions for environment variable issues
func (s *SuggestionEngine) suggestionsFromEnvVars(envVars EnvVarValidation, id *int) []Suggestion {
	suggestions := []Suggestion{}

	// Process required env vars
	for _, envCheck := range envVars.Required {
		if !envCheck.Set {
			suggestion := Suggestion{
				ID:       fmt.Sprintf("env-%d", *id),
				Type:     SuggestionUpdateEnv,
				Severity: SeverityError,
				Title:    fmt.Sprintf("Missing Required Variable: %s", envCheck.Name),
				Message:  fmt.Sprintf("%s is required for %s proxy but is not set.", envCheck.Name, s.proxyType),
				Impact:   envCheck.Impact,
				EnvUpdate: &EnvUpdate{
					Key:            envCheck.Name,
					CurrentValue:   "",
					SuggestedValue: envCheck.Default,
					Reason:         "Required for proxy functionality",
				},
				AutoFixable: true,
			}
			suggestions = append(suggestions, suggestion)
			*id++
		} else if !envCheck.Valid {
			suggestion := Suggestion{
				ID:       fmt.Sprintf("env-%d", *id),
				Type:     SuggestionUpdateEnv,
				Severity: SeverityError,
				Title:    fmt.Sprintf("Invalid Format: %s", envCheck.Name),
				Message:  fmt.Sprintf("%s has invalid format: %s", envCheck.Name, envCheck.Error),
				Impact:   "Configuration validation will fail",
				EnvUpdate: &EnvUpdate{
					Key:            envCheck.Name,
					CurrentValue:   envCheck.Value,
					SuggestedValue: s.suggestFixedValue(envCheck.Name, envCheck.Value),
					Reason:         envCheck.Suggestion,
				},
				AutoFixable: true,
			}
			suggestions = append(suggestions, suggestion)
			*id++
		}
	}

	// Process optional env vars
	for _, envCheck := range envVars.Optional {
		if !envCheck.Set && envCheck.Impact != "" {
			suggestion := Suggestion{
				ID:       fmt.Sprintf("env-%d", *id),
				Type:     SuggestionUpdateEnv,
				Severity: SeverityWarning,
				Title:    fmt.Sprintf("Optional Variable Not Set: %s", envCheck.Name),
				Message:  fmt.Sprintf("%s is not set. Some features may be limited.", envCheck.Name),
				Impact:   envCheck.Impact,
				EnvUpdate: &EnvUpdate{
					Key:            envCheck.Name,
					CurrentValue:   "",
					SuggestedValue: envCheck.Default,
					Reason:         fmt.Sprintf("Enables %s", envCheck.Description),
				},
				AutoFixable: true,
			}
			suggestions = append(suggestions, suggestion)
			*id++
		}
	}

	return suggestions
}

// suggestionsFromHostPaths generates suggestions for host path issues
func (s *SuggestionEngine) suggestionsFromHostPaths(layer LayerValidation, id *int) []Suggestion {
	suggestions := []Suggestion{}

	for _, check := range layer.Checks {
		if !check.Exists {
			suggestionType := SuggestionCreateFile
			if check.Type == "directory" {
				suggestionType = SuggestionCreateDirectory
			}

			severity := SeverityWarning
			if check.Severity == SeverityError {
				severity = SeverityError
			}

			suggestion := Suggestion{
				ID:       fmt.Sprintf("path-%d", *id),
				Type:     suggestionType,
				Severity: severity,
				Title:    fmt.Sprintf("Create %s: %s", check.Type, filepath.Base(check.Path)),
				Message:  fmt.Sprintf("Required %s does not exist on host filesystem", check.Type),
				Impact:   check.Error,
				Command:  s.getCreateCommand(check.Path, check.Type),
				FileCreate: &FileCreate{
					Path:        check.Path,
					Type:        check.Type,
					Permissions: "0755",
					Reason:      check.Suggestion,
				},
				AutoFixable: false, // Requires user confirmation
			}
			suggestions = append(suggestions, suggestion)
			*id++
		} else if !check.Accessible {
			suggestion := Suggestion{
				ID:       fmt.Sprintf("path-%d", *id),
				Type:     SuggestionFixPermissions,
				Severity: SeverityError,
				Title:    fmt.Sprintf("Fix Permissions: %s", filepath.Base(check.Path)),
				Message:  fmt.Sprintf("%s exists but is not accessible", check.Path),
				Impact:   "File cannot be read by the manager",
				Command:  fmt.Sprintf("chmod 644 %s", check.Path),
				AutoFixable: false,
			}
			suggestions = append(suggestions, suggestion)
			*id++
		}
	}

	return suggestions
}

// suggestionsFromVolumeMappings generates suggestions for volume mapping issues
func (s *SuggestionEngine) suggestionsFromVolumeMappings(layer LayerValidation, id *int) []Suggestion {
	suggestions := []Suggestion{}

	for _, check := range layer.Checks {
		if !check.Valid {
			// Parse expected location to get host and container paths
			parts := strings.Split(check.ExpectedLocation, " -> ")
			if len(parts) == 2 {
				suggestion := Suggestion{
					ID:       fmt.Sprintf("vol-%d", *id),
					Type:     SuggestionAddVolume,
					Severity: SeverityError,
					Title:    fmt.Sprintf("Add Volume Mapping: %s", filepath.Base(check.Path)),
					Message:  "Required volume mapping not found in container",
					Impact:   check.Error,
					VolumeUpdate: &VolumeUpdate{
						HostPath:      parts[0],
						ContainerPath: parts[1],
						Mode:          "ro",
						Service:       s.proxyType,
						Reason:        check.Suggestion,
					},
					Command:     fmt.Sprintf("Add to docker-compose.yml:\n  volumes:\n    - %s:%s:ro", parts[0], parts[1]),
					AutoFixable: false,
				}
				suggestions = append(suggestions, suggestion)
				*id++
			}
		}
	}

	return suggestions
}

// suggestionsFromContainerPaths generates suggestions for container path issues
func (s *SuggestionEngine) suggestionsFromContainerPaths(layer LayerValidation, id *int) []Suggestion {
	suggestions := []Suggestion{}

	for _, check := range layer.Checks {
		if check.Type == "container" && !check.Valid {
			suggestion := Suggestion{
				ID:       fmt.Sprintf("container-%d", *id),
				Type:     SuggestionStartContainer,
				Severity: SeverityError,
				Title:    "Start Container",
				Message:  check.Error,
				Impact:   "Cannot validate container paths while container is stopped",
				Command:  check.Suggestion,
				AutoFixable: false,
			}
			suggestions = append(suggestions, suggestion)
			*id++
		} else if !check.Accessible {
			suggestion := Suggestion{
				ID:       fmt.Sprintf("container-%d", *id),
				Type:     SuggestionAddVolume,
				Severity: SeverityError,
				Title:    fmt.Sprintf("Fix Container Path Access: %s", filepath.Base(check.Path)),
				Message:  "Path not accessible from inside container",
				Impact:   check.Error,
				Command:  check.Suggestion,
				AutoFixable: false,
			}
			suggestions = append(suggestions, suggestion)
			*id++
		}
	}

	return suggestions
}

// suggestOptimizations generates optimization suggestions
func (s *SuggestionEngine) suggestOptimizations(result *ValidationResult, id *int) []Suggestion {
	suggestions := []Suggestion{}

	// Suggest removing unnecessary env vars that match defaults
	defaultMatches := []string{}
	for _, envCheck := range result.EnvVars.All {
		if envCheck.Set && envCheck.Value == envCheck.Default {
			defaultMatches = append(defaultMatches, envCheck.Name)
		}
	}

	if len(defaultMatches) > 3 {
		suggestion := Suggestion{
			ID:       fmt.Sprintf("opt-%d", *id),
			Type:     SuggestionRemoveEnv,
			Severity: SeverityInfo,
			Title:    "Simplify Configuration",
			Message:  fmt.Sprintf("Found %d environment variables set to default values", len(defaultMatches)),
			Impact:   "Removing these will make your .env file cleaner and easier to maintain",
			Command:  fmt.Sprintf("Remove from .env:\n%s", strings.Join(defaultMatches, "\n")),
			AutoFixable: false,
		}
		suggestions = append(suggestions, suggestion)
		*id++
	}

	// Suggest using production settings for development mode
	if result.ProxyType != "standalone" {
		envValue := ""
		for _, envCheck := range result.EnvVars.All {
			if envCheck.Name == "ENVIRONMENT" {
				envValue = envCheck.Value
				break
			}
		}

		if envValue == "development" {
			suggestion := Suggestion{
				ID:       fmt.Sprintf("opt-%d", *id),
				Type:     SuggestionUpdateEnv,
				Severity: SeverityInfo,
				Title:    "Consider Production Mode",
				Message:  "Running in development mode. Consider switching to production for better performance.",
				Impact:   "Production mode enables optimizations and disables debug features",
				EnvUpdate: &EnvUpdate{
					Key:            "ENVIRONMENT",
					CurrentValue:   "development",
					SuggestedValue: "production",
					Reason:         "Better performance and security",
				},
				AutoFixable: true,
			}
			suggestions = append(suggestions, suggestion)
			*id++
		}
	}

	return suggestions
}

// getCreateCommand returns a shell command to create a file or directory
func (s *SuggestionEngine) getCreateCommand(path, pathType string) string {
	if pathType == "directory" {
		return fmt.Sprintf("mkdir -p %s", path)
	}
	return fmt.Sprintf("mkdir -p %s && touch %s", filepath.Dir(path), path)
}

// suggestFixedValue suggests a fixed value for an invalid env var
func (s *SuggestionEngine) suggestFixedValue(envVar, currentValue string) string {
	// Fix path issues
	if strings.Contains(envVar, "_PATH") || strings.Contains(envVar, "_CONFIG") || strings.Contains(envVar, "_LOG") || strings.Contains(envVar, "_DIR") {
		fixed := currentValue
		// Add leading slash if missing
		if !strings.HasPrefix(fixed, "/") {
			fixed = "/" + strings.TrimPrefix(fixed, "./")
		}
		// Remove trailing slash
		if strings.HasSuffix(fixed, "/") && fixed != "/" {
			fixed = strings.TrimSuffix(fixed, "/")
		}
		return fixed
	}

	// Fix container name issues
	if strings.HasSuffix(envVar, "_CONTAINER_NAME") {
		// Remove invalid characters
		fixed := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-' {
				return r
			}
			return '-'
		}, currentValue)
		return fixed
	}

	return currentValue
}

// GenerateEnvFile generates a .env file content with all suggestions applied
func (s *SuggestionEngine) GenerateEnvFile(result *ValidationResult, suggestions []Suggestion) string {
	lines := []string{
		"# CrowdSec Manager Environment Configuration",
		fmt.Sprintf("# Generated: %s", result.Timestamp.Format("2006-01-02 15:04:05")),
		fmt.Sprintf("# Proxy Type: %s", result.ProxyType),
		"",
		"# ============================================================================",
		"# CORE CONFIGURATION",
		"# ============================================================================",
		"",
	}

	// Group env vars by category
	coreVars := []string{"PROXY_TYPE", "PROXY_ENABLED", "ENVIRONMENT", "LOG_LEVEL"}
	proxyVars := []string{}
	pathVars := []string{}

	for _, envCheck := range result.EnvVars.Required {
		if contains(coreVars, envCheck.Name) {
			continue
		}
		if strings.Contains(envCheck.Name, "_PATH") || strings.Contains(envCheck.Name, "_CONFIG") || strings.Contains(envCheck.Name, "_DIR") || strings.Contains(envCheck.Name, "_LOG") {
			pathVars = append(pathVars, envCheck.Name)
		} else {
			proxyVars = append(proxyVars, envCheck.Name)
		}
	}

	// Add core vars
	lines = append(lines, fmt.Sprintf("PROXY_TYPE=%s", result.ProxyType))
	lines = append(lines, "PROXY_ENABLED=true")
	lines = append(lines, "ENVIRONMENT=production")
	lines = append(lines, "LOG_LEVEL=info")
	lines = append(lines, "")

	// Add proxy vars
	if len(proxyVars) > 0 {
		lines = append(lines, "# ============================================================================")
		lines = append(lines, fmt.Sprintf("# %s CONFIGURATION", strings.ToUpper(result.ProxyType)))
		lines = append(lines, "# ============================================================================")
		lines = append(lines, "")

		for _, varName := range proxyVars {
			for _, envCheck := range result.EnvVars.Required {
				if envCheck.Name == varName {
					value := envCheck.Value
					if value == "" {
						value = envCheck.Default
					}
					lines = append(lines, fmt.Sprintf("%s=%s", envCheck.Name, value))
				}
			}
		}
		lines = append(lines, "")
	}

	// Add path vars
	if len(pathVars) > 0 {
		lines = append(lines, "# ============================================================================")
		lines = append(lines, "# PATH CONFIGURATION (Container-Internal Paths)")
		lines = append(lines, "# ============================================================================")
		lines = append(lines, "")

		for _, varName := range pathVars {
			for _, envCheck := range result.EnvVars.Required {
				if envCheck.Name == varName {
					value := envCheck.Value
					if value == "" {
						value = envCheck.Default
					}
					lines = append(lines, fmt.Sprintf("%s=%s", envCheck.Name, value))
				}
			}
		}
	}

	return strings.Join(lines, "\n")
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
