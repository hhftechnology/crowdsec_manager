package config

import "time"

// ValidationSeverity represents the severity level of a validation issue
type ValidationSeverity string

const (
	SeverityError   ValidationSeverity = "error"
	SeverityWarning ValidationSeverity = "warning"
	SeverityInfo    ValidationSeverity = "info"
)

// ValidationStatus represents the overall status of a validation check
type ValidationStatus string

const (
	StatusValid   ValidationStatus = "valid"
	StatusWarning ValidationStatus = "warning"
	StatusError   ValidationStatus = "error"
)

// LayerType represents the validation layer being checked
type LayerType string

const (
	LayerHost      LayerType = "host"
	LayerVolume    LayerType = "volume"
	LayerContainer LayerType = "container"
)

// ValidationResult contains the complete validation results
type ValidationResult struct {
	Valid       bool                       `json:"valid"`
	ProxyType   string                     `json:"proxy_type"`
	Timestamp   time.Time                  `json:"timestamp"`
	Summary     ValidationSummary          `json:"summary"`
	EnvVars     EnvVarValidation           `json:"env_vars"`
	Layers      LayerValidations           `json:"layers"`
	Suggestions []Suggestion               `json:"suggestions"`
	Errors      []ValidationError          `json:"errors"`
	Warnings    []ValidationWarning        `json:"warnings"`
}

// ValidationSummary provides a quick overview of validation status
type ValidationSummary struct {
	TotalChecks    int              `json:"total_checks"`
	PassedChecks   int              `json:"passed_checks"`
	FailedChecks   int              `json:"failed_checks"`
	WarningChecks  int              `json:"warning_checks"`
	OverallStatus  ValidationStatus `json:"overall_status"`
	ReadyToDeploy  bool             `json:"ready_to_deploy"`
}

// EnvVarValidation contains environment variable validation results
type EnvVarValidation struct {
	Required []EnvVarCheck `json:"required"`
	Optional []EnvVarCheck `json:"optional"`
	Custom   []EnvVarCheck `json:"custom"`
	All      []EnvVarCheck `json:"all"`
}

// EnvVarCheck represents validation of a single environment variable
type EnvVarCheck struct {
	Name         string             `json:"name"`
	Value        string             `json:"value"`
	Required     bool               `json:"required"`
	Valid        bool               `json:"valid"`
	Set          bool               `json:"set"`
	Default      string             `json:"default"`
	Description  string             `json:"description"`
	Error        string             `json:"error,omitempty"`
	Suggestion   string             `json:"suggestion,omitempty"`
	Severity     ValidationSeverity `json:"severity"`
	Impact       string             `json:"impact,omitempty"`
}

// LayerValidations contains validation results for all three layers
type LayerValidations struct {
	HostPaths      LayerValidation `json:"host_paths"`
	VolumeMappings LayerValidation `json:"volume_mappings"`
	ContainerPaths LayerValidation `json:"container_paths"`
}

// LayerValidation represents validation results for a specific layer
type LayerValidation struct {
	Status ValidationStatus  `json:"status"`
	Checks []ValidationCheck `json:"checks"`
}

// ValidationCheck represents a single validation check
type ValidationCheck struct {
	Layer            LayerType          `json:"layer"`
	Path             string             `json:"path"`
	Type             string             `json:"type"` // file, directory, volume
	Exists           bool               `json:"exists"`
	Accessible       bool               `json:"accessible"`
	ExpectedLocation string             `json:"expected_location"`
	ActualLocation   string             `json:"actual_location,omitempty"`
	Valid            bool               `json:"valid"`
	Error            string             `json:"error,omitempty"`
	Suggestion       string             `json:"suggestion,omitempty"`
	Severity         ValidationSeverity `json:"severity"`
	Details          map[string]string  `json:"details,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	Layer      LayerType `json:"layer"`
	Code       string    `json:"code"`
	Message    string    `json:"message"`
	Path       string    `json:"path,omitempty"`
	EnvVar     string    `json:"env_var,omitempty"`
	Suggestion string    `json:"suggestion,omitempty"`
	Impact     string    `json:"impact,omitempty"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	Layer      LayerType `json:"layer"`
	Code       string    `json:"code"`
	Message    string    `json:"message"`
	Path       string    `json:"path,omitempty"`
	EnvVar     string    `json:"env_var,omitempty"`
	Suggestion string    `json:"suggestion,omitempty"`
	Impact     string    `json:"impact,omitempty"`
}

// Suggestion represents an actionable suggestion to fix issues
type Suggestion struct {
	ID           string             `json:"id"`
	Type         SuggestionType     `json:"type"`
	Severity     ValidationSeverity `json:"severity"`
	Title        string             `json:"title"`
	Message      string             `json:"message"`
	Impact       string             `json:"impact"`
	Command      string             `json:"command,omitempty"`
	EnvUpdate    *EnvUpdate         `json:"env_update,omitempty"`
	VolumeUpdate *VolumeUpdate      `json:"volume_update,omitempty"`
	FileCreate   *FileCreate        `json:"file_create,omitempty"`
	AutoFixable  bool               `json:"auto_fixable"`
	AppliedAt    *time.Time         `json:"applied_at,omitempty"`
}

// SuggestionType represents the type of suggestion
type SuggestionType string

const (
	SuggestionCreateFile      SuggestionType = "create_file"
	SuggestionCreateDirectory SuggestionType = "create_directory"
	SuggestionFixPath         SuggestionType = "fix_path"
	SuggestionAddVolume       SuggestionType = "add_volume"
	SuggestionUpdateEnv       SuggestionType = "update_env"
	SuggestionRemoveEnv       SuggestionType = "remove_env"
	SuggestionStartContainer  SuggestionType = "start_container"
	SuggestionFixPermissions  SuggestionType = "fix_permissions"
)

// EnvUpdate represents an environment variable update suggestion
type EnvUpdate struct {
	Key            string `json:"key"`
	CurrentValue   string `json:"current_value"`
	SuggestedValue string `json:"suggested_value"`
	Reason         string `json:"reason"`
}

// VolumeUpdate represents a volume mapping update suggestion
type VolumeUpdate struct {
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
	Mode          string `json:"mode"` // ro, rw
	Service       string `json:"service"`
	Reason        string `json:"reason"`
}

// FileCreate represents a file creation suggestion
type FileCreate struct {
	Path        string `json:"path"`
	Type        string `json:"type"` // file, directory
	Content     string `json:"content,omitempty"`
	Permissions string `json:"permissions"`
	Reason      string `json:"reason"`
}

// VolumeMapping represents a Docker volume mapping
type VolumeMapping struct {
	Type        string `json:"type"`        // bind, volume, tmpfs
	Source      string `json:"source"`      // Host path
	Destination string `json:"destination"` // Container path
	Mode        string `json:"mode"`        // ro, rw
	RW          bool   `json:"rw"`
}

// ProxyRequirements defines the validation requirements for each proxy type
type ProxyRequirements struct {
	ProxyType        string              `json:"proxy_type"`
	RequiredEnvVars  []string            `json:"required_env_vars"`
	OptionalEnvVars  []string            `json:"optional_env_vars"`
	RequiredPaths    []PathRequirement   `json:"required_paths"`
	OptionalPaths    []PathRequirement   `json:"optional_paths"`
	RequiredVolumes  []VolumeRequirement `json:"required_volumes"`
	Features         []string            `json:"features"`
}

// PathRequirement defines a required path and its characteristics
type PathRequirement struct {
	EnvVar        string `json:"env_var"`
	DefaultPath   string `json:"default_path"`
	Type          string `json:"type"` // file, directory
	Required      bool   `json:"required"`
	Description   string `json:"description"`
	HostPath      string `json:"host_path"`       // Expected host path
	ContainerPath string `json:"container_path"`  // Path inside container
	FeatureNeeded string `json:"feature_needed"`  // Which feature needs this
}

// VolumeRequirement defines a required volume mapping
type VolumeRequirement struct {
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
	Mode          string `json:"mode"`
	Required      bool   `json:"required"`
	Description   string `json:"description"`
}
