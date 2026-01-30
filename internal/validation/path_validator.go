package validation

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PathExistsResult represents the result of a path validation check
type PathExistsResult struct {
	Exists      bool   `json:"exists"`
	IsDirectory bool   `json:"is_directory"`
	IsFile      bool   `json:"is_file"`
	Readable    bool   `json:"readable"`
	Writable    bool   `json:"writable"`
	Path        string `json:"path"`
	Error       string `json:"error,omitempty"`
}

// PathValidationWarning represents a warning about a path configuration
type PathValidationWarning struct {
	Path        string `json:"path"`
	ConfigKey   string `json:"config_key"`
	Warning     string `json:"warning"`
	Severity    string `json:"severity"` // "error", "warning", "info"
	Suggestion  string `json:"suggestion,omitempty"`
}

// DockerExecutor is an interface for executing commands in Docker containers
type DockerExecutor interface {
	ExecCommand(containerName string, cmd []string) (string, error)
	FileExists(containerName string, path string) (bool, error)
}

// ValidateHostPath checks if a path exists on the host filesystem and returns detailed info
func ValidateHostPath(path string, expectedType string) PathExistsResult {
	result := PathExistsResult{
		Path: path,
	}

	if path == "" {
		result.Error = "path is empty"
		return result
	}

	// Clean and normalize the path
	cleanPath := filepath.Clean(path)

	// Check if path exists
	info, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			result.Error = "path does not exist"
		} else if os.IsPermission(err) {
			result.Error = "permission denied"
		} else {
			result.Error = err.Error()
		}
		return result
	}

	result.Exists = true
	result.IsDirectory = info.IsDir()
	result.IsFile = !info.IsDir()

	// Check type expectation
	if expectedType == "file" && result.IsDirectory {
		result.Error = "expected a file but found a directory"
		return result
	}
	if expectedType == "directory" && result.IsFile {
		result.Error = "expected a directory but found a file"
		return result
	}

	// Check readability
	if result.IsFile {
		file, err := os.Open(cleanPath)
		if err == nil {
			file.Close()
			result.Readable = true
		}
	} else {
		// For directories, try to read directory contents
		_, err := os.ReadDir(cleanPath)
		result.Readable = err == nil
	}

	// Check writability
	if result.IsFile {
		// For files, check if we can open for writing
		file, err := os.OpenFile(cleanPath, os.O_WRONLY, 0)
		if err == nil {
			file.Close()
			result.Writable = true
		}
	} else {
		// For directories, try to create a temp file
		tempFile := filepath.Join(cleanPath, ".write_test_"+fmt.Sprintf("%d", os.Getpid()))
		file, err := os.Create(tempFile)
		if err == nil {
			file.Close()
			os.Remove(tempFile)
			result.Writable = true
		}
	}

	return result
}

// EnsureDirectoryExists creates a directory if it doesn't exist
func EnsureDirectoryExists(path string) error {
	if path == "" {
		return fmt.Errorf("path cannot be empty")
	}

	cleanPath := filepath.Clean(path)

	// Check if it already exists
	info, err := os.Stat(cleanPath)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("path exists but is not a directory: %s", cleanPath)
		}
		return nil // Already exists as directory
	}

	if !os.IsNotExist(err) {
		return fmt.Errorf("failed to check path: %w", err)
	}

	// Create the directory with parents
	if err := os.MkdirAll(cleanPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", cleanPath, err)
	}

	return nil
}

// ValidateContainerPath checks if a path exists inside a Docker container
func ValidateContainerPath(dockerClient DockerExecutor, containerName, path string) PathExistsResult {
	result := PathExistsResult{
		Path: path,
	}

	if containerName == "" {
		result.Error = "container name is empty"
		return result
	}
	if path == "" {
		result.Error = "path is empty"
		return result
	}

	// Use stat to check if path exists
	output, err := dockerClient.ExecCommand(containerName, []string{
		"stat", "-c", "%F", path,
	})
	if err != nil {
		result.Error = fmt.Sprintf("path does not exist or is inaccessible: %v", err)
		return result
	}

	output = strings.TrimSpace(output)
	result.Exists = true

	switch {
	case strings.Contains(output, "regular"):
		result.IsFile = true
	case strings.Contains(output, "directory"):
		result.IsDirectory = true
	default:
		// Some other type (symlink, etc.) - mark as file for simplicity
		result.IsFile = true
	}

	// Check readability
	_, readErr := dockerClient.ExecCommand(containerName, []string{
		"test", "-r", path,
	})
	result.Readable = readErr == nil

	// Check writability
	_, writeErr := dockerClient.ExecCommand(containerName, []string{
		"test", "-w", path,
	})
	result.Writable = writeErr == nil

	return result
}

// ValidatePath is a general path validation that works for both host and container paths
func ValidatePath(path string) ValidationResult {
	path = strings.TrimSpace(path)
	if path == "" {
		return ValidationResult{Valid: false, Message: "path cannot be empty"}
	}

	// Check for null bytes (security issue)
	if strings.Contains(path, "\x00") {
		return ValidationResult{
			Valid:   false,
			Message: "path contains null bytes",
			Value:   path,
		}
	}

	// Check for path traversal attempts
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") && !filepath.IsAbs(path) {
		return ValidationResult{
			Valid:   false,
			Message: "relative path traversal detected",
			Value:   path,
		}
	}

	// Paths should typically be absolute for container operations
	if !filepath.IsAbs(path) && !strings.HasPrefix(path, "./") {
		return ValidationResult{
			Valid:   false,
			Message: "path should be absolute or start with ./",
			Value:   path,
		}
	}

	return ValidationResult{Valid: true, Value: cleanPath}
}

// ValidateYAMLFilePath validates that a path points to a YAML file
func ValidateYAMLFilePath(path string) ValidationResult {
	result := ValidatePath(path)
	if !result.Valid {
		return result
	}

	// Check extension
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yaml" && ext != ".yml" {
		return ValidationResult{
			Valid:   false,
			Message: "file must have .yaml or .yml extension",
			Value:   path,
		}
	}

	return ValidationResult{Valid: true, Value: result.Value}
}

// ValidateDirectoryPath validates that a path looks like a directory path
func ValidateDirectoryPath(path string) ValidationResult {
	result := ValidatePath(path)
	if !result.Valid {
		return result
	}

	// A directory path shouldn't have a file extension (heuristic)
	// But we don't enforce this strictly as some dirs might have dots in names
	ext := filepath.Ext(path)
	if ext != "" && (ext == ".yaml" || ext == ".yml" || ext == ".conf" || ext == ".json") {
		return ValidationResult{
			Valid:   false,
			Message: "path appears to be a file path, not a directory",
			Value:   path,
		}
	}

	return ValidationResult{Valid: true, Value: result.Value}
}

// SanitizePath removes or escapes dangerous characters from a path
// for safe use in shell commands
func SanitizePath(path string) string {
	if path == "" {
		return ""
	}

	// Remove null bytes
	path = strings.ReplaceAll(path, "\x00", "")

	// Remove newlines
	path = strings.ReplaceAll(path, "\n", "")
	path = strings.ReplaceAll(path, "\r", "")

	// Remove shell metacharacters that could be dangerous
	// But keep /, ., -, _ which are valid in paths
	dangerous := []string{";", "|", "&", "$", "`", "(", ")", "{", "}", "[", "]", "<", ">", "!", "*", "?", "#", "~"}
	for _, char := range dangerous {
		path = strings.ReplaceAll(path, char, "")
	}

	return filepath.Clean(path)
}
