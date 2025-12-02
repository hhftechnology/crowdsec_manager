package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestUpdateProfilesYaml(t *testing.T) {
	tmpDir := t.TempDir()
	profilesPath := filepath.Join(tmpDir, "profiles.yaml")

	// Helper to read file content
	readContent := func() string {
		data, err := os.ReadFile(profilesPath)
		if err != nil {
			return ""
		}
		return string(data)
	}

	// 1. Test Enable on non-existent file
	t.Log("Testing Enable on non-existent file")
	err := updateProfilesYaml(profilesPath, true)
	if err != nil {
		t.Fatalf("Failed to enable on new file: %v", err)
	}
	content := readContent()
	t.Logf("Content after enable: %s", content)
	if !strings.Contains(content, "name: default_ip_remediation") {
		t.Errorf("Expected profile 'default_ip_remediation' to be created")
	}
	if !strings.Contains(content, "- discord") {
		t.Errorf("Expected 'discord' notification to be added")
	}

	// 2. Test Enable on existing file with profile but no notifications
	t.Log("Testing Enable on existing file with profile but no notifications")
	initialYaml := `
- name: default_ip_remediation
  filters:
   - Alert.Remediation == true
  decisions:
   - type: ban
     duration: 4h
  on_success: break
`
	os.WriteFile(profilesPath, []byte(initialYaml), 0644)
	
	err = updateProfilesYaml(profilesPath, true)
	if err != nil {
		t.Fatalf("Failed to enable on existing profile: %v", err)
	}
	content = readContent()
	t.Logf("Content after enable (existing): %s", content)
	if !strings.Contains(content, "notifications:") {
		t.Errorf("Expected 'notifications' section to be added")
	}
	if !strings.Contains(content, "- discord") {
		t.Errorf("Expected 'discord' notification to be added")
	}

	// 3. Test Enable on existing file with other notifications
	t.Log("Testing Enable on existing file with other notifications")
	initialYaml = `
- name: default_ip_remediation
  notifications:
   - slack
`
	os.WriteFile(profilesPath, []byte(initialYaml), 0644)
	
	err = updateProfilesYaml(profilesPath, true)
	if err != nil {
		t.Fatalf("Failed to enable with existing notifications: %v", err)
	}
	content = readContent()
	t.Logf("Content after enable (other notifications): %s", content)
	if !strings.Contains(content, "- slack") {
		t.Errorf("Expected 'slack' to be preserved")
	}
	if !strings.Contains(content, "- discord") {
		t.Errorf("Expected 'discord' to be added")
	}

	// 4. Test Disable
	t.Log("Testing Disable")
	err = updateProfilesYaml(profilesPath, false)
	if err != nil {
		t.Fatalf("Failed to disable: %v", err)
	}
	content = readContent()
	t.Logf("Content after disable: %s", content)
	if !strings.Contains(content, "- slack") {
		t.Errorf("Expected 'slack' to be preserved after disable")
	}
	if strings.Contains(content, "- discord") {
		t.Errorf("Expected 'discord' to be removed")
	}

	// 5. Test Enable with commented out notifications
	t.Log("Testing Enable with commented out notifications")
	initialYaml = `
- name: default_ip_remediation
  # notifications:
  #  - slack
`
	os.WriteFile(profilesPath, []byte(initialYaml), 0644)
	err = updateProfilesYaml(profilesPath, true)
	if err != nil {
		t.Fatalf("Failed to enable with comments: %v", err)
	}
	content = readContent()
	t.Logf("Content after enable (commented): %s", content)
	if !strings.Contains(content, "notifications:") {
		t.Errorf("Expected 'notifications' section to be added")
	}
	if !strings.Contains(content, "- discord") {
		t.Errorf("Expected 'discord' to be added")
	}
	
	// Verify structure is valid YAML
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(content), &node); err != nil {
		t.Errorf("Resulting YAML is invalid: %v", err)
	}
}
