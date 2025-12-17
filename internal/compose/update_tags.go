package compose

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// UpdateComposeFileTags updates service image tags in a docker-compose file.
// serviceTags is a map of service names to their new tags.
// This function preserves the structure and comments of the compose file.
func UpdateComposeFileTags(filePath string, serviceTags map[string]string) error {
	// Read the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read compose file: %w", err)
	}

	lines := strings.Split(string(content), "\n")
	modified := false
	currentService := ""
	inServices := false

	// Regular expression to match service name at services level (2 spaces indentation)
	servicePattern := regexp.MustCompile(`^  ([a-zA-Z0-9_-]+):`)
	// Regular expression to match image line (4 spaces indentation)
	imagePattern := regexp.MustCompile(`^(    image:\s*)(.+)$`)

	for i, line := range lines {
		// Check if we're entering the services section
		if strings.HasPrefix(line, "services:") {
			inServices = true
			continue
		}

		// Check if we're leaving the services section (another top-level key)
		if inServices && len(line) > 0 && line[0] != ' ' && line[0] != '#' && strings.Contains(line, ":") {
			inServices = false
		}

		if !inServices {
			continue
		}

		// Check if this line defines a service
		if matches := servicePattern.FindStringSubmatch(line); matches != nil {
			currentService = matches[1]
			continue
		}

		// Check if this is an image line for a service we want to update
		if currentService != "" {
			if newTag, exists := serviceTags[currentService]; exists && newTag != "" {
				if matches := imagePattern.FindStringSubmatch(line); matches != nil {
					imagePrefix := matches[1]
					currentImage := matches[2]

					// Extract the image name (without tag)
					imageName := currentImage
					if colonIdx := strings.LastIndex(currentImage, ":"); colonIdx != -1 {
						imageName = currentImage[:colonIdx]
					}

					// Create new image line with updated tag
					newImageLine := fmt.Sprintf("%s%s:%s", imagePrefix, imageName, newTag)
					if lines[i] != newImageLine {
						lines[i] = newImageLine
						modified = true
					}
				}
			}
		}
	}

	if !modified {
		return nil // No changes needed
	}

	// Write the modified content back
	output := strings.Join(lines, "\n")
	if err := os.WriteFile(filePath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write compose file: %w", err)
	}

	return nil
}
