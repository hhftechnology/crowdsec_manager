package compose

import (
	"bufio"
	"os"
	"strings"
)

// ScanResult holds discovered environment variable values and their source file.
type ScanResult struct {
	Values map[string]string `json:"values"`
	Source string            `json:"source"` // file path of the last file that contributed values
	Found  bool              `json:"found"`
}

// ScanServiceEnvVars reads a compose file and extracts env var values for the given keys
// across all services (or specific services if serviceNames is non-empty).
// This is a READ-ONLY operation that never modifies the file.
func ScanServiceEnvVars(composePath string, serviceNames []string, keys []string) (*ScanResult, error) {
	result := &ScanResult{
		Values: make(map[string]string),
		Source: composePath,
	}

	keySet := make(map[string]bool, len(keys))
	for _, k := range keys {
		keySet[k] = true
	}

	serviceFilter := make(map[string]bool, len(serviceNames))
	for _, s := range serviceNames {
		serviceFilter[s] = true
	}

	// Try structured parsing first via compose-go.
	project, err := LoadComposeFile(composePath)
	if err == nil {
		for svcName, svc := range project.Services {
			if len(serviceFilter) > 0 && !serviceFilter[svcName] {
				continue
			}
			for envKey, envVal := range svc.Environment {
				if keySet[envKey] && envVal != nil && *envVal != "" {
					result.Values[envKey] = *envVal
				}
			}
		}
		result.Found = len(result.Values) > 0
		return result, nil
	}

	// Fallback: raw line-based scanning for when compose-go fails (e.g. missing env vars).
	return scanEnvVarsRaw(composePath, keys)
}

// scanEnvVarsRaw does a simple line-based scan of a compose file for KEY=value or KEY: value patterns.
func scanEnvVarsRaw(composePath string, keys []string) (*ScanResult, error) {
	result := &ScanResult{
		Values: make(map[string]string),
		Source: composePath,
	}

	f, err := os.Open(composePath)
	if err != nil {
		return result, err
	}
	defer f.Close()

	keySet := make(map[string]bool, len(keys))
	for _, k := range keys {
		keySet[k] = true
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Handle "- KEY=value" sequence format.
		if strings.HasPrefix(line, "- ") {
			line = strings.TrimPrefix(line, "- ")
			line = strings.Trim(line, "\"'")
		}

		// Try KEY=value first.
		if idx := strings.Index(line, "="); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			val = strings.Trim(val, "\"'")
			if keySet[key] && val != "" {
				result.Values[key] = val
			}
			continue
		}

		// Try KEY: value (YAML mapping style).
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			val = strings.Trim(val, "\"'")
			if keySet[key] && val != "" {
				result.Values[key] = val
			}
		}
	}

	result.Found = len(result.Values) > 0
	return result, scanner.Err()
}

// ScanMultipleComposeFiles scans multiple compose files for env vars and returns the merged result.
// Later files override earlier ones (last-wins). Files that do not exist or cannot be parsed are
// silently skipped so a missing optional compose file never causes an error.
func ScanMultipleComposeFiles(composePaths []string, serviceNames []string, keys []string) (*ScanResult, error) {
	merged := &ScanResult{
		Values: make(map[string]string),
	}

	for _, path := range composePaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		result, err := ScanServiceEnvVars(path, serviceNames, keys)
		if err != nil {
			continue // Skip files that cannot be parsed.
		}
		for k, v := range result.Values {
			merged.Values[k] = v
			merged.Source = path // Track the last source that contributed values.
		}
	}

	merged.Found = len(merged.Values) > 0
	return merged, nil
}
