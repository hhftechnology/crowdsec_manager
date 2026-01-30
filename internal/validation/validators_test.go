package validation

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateIP(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		valid   bool
		message string
	}{
		{"valid IPv4", "192.168.1.1", true, ""},
		{"valid IPv4 with whitespace", "  192.168.1.1  ", true, ""},
		{"valid IPv6", "::1", true, ""},
		{"valid IPv6 full", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", true, ""},
		{"invalid IP", "not-an-ip", false, MsgInvalidIP},
		{"empty string", "", false, MsgEmptyValue},
		{"partial IP", "192.168.1", false, MsgInvalidIP},
		{"IP with port", "192.168.1.1:8080", false, MsgInvalidIP},
		{"CIDR notation", "192.168.1.0/24", false, MsgInvalidIP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateIP(tt.input)
			if result.Valid != tt.valid {
				t.Errorf("ValidateIP(%q) = %v, want %v", tt.input, result.Valid, tt.valid)
			}
			if !tt.valid && result.Message != tt.message {
				t.Errorf("ValidateIP(%q) message = %q, want %q", tt.input, result.Message, tt.message)
			}
		})
	}
}

func TestValidateCIDR(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		valid   bool
		message string
	}{
		{"valid CIDR /24", "192.168.1.0/24", true, ""},
		{"valid CIDR /32", "192.168.1.1/32", true, ""},
		{"valid CIDR /8", "10.0.0.0/8", true, ""},
		{"valid IPv6 CIDR", "2001:db8::/32", true, ""},
		{"valid CIDR with whitespace", "  10.0.0.0/8  ", true, ""},
		{"invalid - no prefix", "192.168.1.0", false, MsgInvalidCIDR},
		{"invalid - bad prefix", "192.168.1.0/33", false, MsgInvalidCIDR},
		{"invalid - not a network", "not-a-cidr", false, MsgInvalidCIDR},
		{"empty string", "", false, MsgEmptyValue},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCIDR(tt.input)
			if result.Valid != tt.valid {
				t.Errorf("ValidateCIDR(%q) = %v, want %v", tt.input, result.Valid, tt.valid)
			}
			if !tt.valid && result.Message != tt.message {
				t.Errorf("ValidateCIDR(%q) message = %q, want %q", tt.input, result.Message, tt.message)
			}
		})
	}
}

func TestValidateIPOrCIDR(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"valid IP", "192.168.1.1", true},
		{"valid CIDR", "192.168.1.0/24", true},
		{"valid IPv6", "::1", true},
		{"valid IPv6 CIDR", "2001:db8::/32", true},
		{"invalid", "not-valid", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateIPOrCIDR(tt.input)
			if result.Valid != tt.valid {
				t.Errorf("ValidateIPOrCIDR(%q) = %v, want %v", tt.input, result.Valid, tt.valid)
			}
		})
	}
}

func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"valid HTTPS", "https://example.com/webhook", true},
		{"valid with path", "https://hooks.slack.com/services/XXX", true},
		{"HTTP not allowed", "http://example.com/webhook", false},
		{"no scheme", "example.com/webhook", false},
		{"empty", "", false},
		{"invalid URL", "not-a-url", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateWebhookURL(tt.input)
			if result.Valid != tt.valid {
				t.Errorf("ValidateWebhookURL(%q) = %v, want %v", tt.input, result.Valid, tt.valid)
			}
		})
	}
}

func TestValidateDiscordWebhookURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"valid Discord URL", "https://discord.com/api/webhooks/123456789/abcdeftoken", true},
		{"valid discordapp URL", "https://discordapp.com/api/webhooks/123/token", true},
		{"missing token", "https://discord.com/api/webhooks/123", false},
		{"wrong host", "https://example.com/api/webhooks/123/token", false},
		{"wrong path", "https://discord.com/webhooks/123/token", false},
		{"HTTP not allowed", "http://discord.com/api/webhooks/123/token", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateDiscordWebhookURL(tt.input)
			if result.Valid != tt.valid {
				t.Errorf("ValidateDiscordWebhookURL(%q) = %v, want %v", tt.input, result.Valid, tt.valid)
			}
		})
	}
}

func TestValidateCaptchaProvider(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"turnstile", "turnstile", true},
		{"recaptcha", "recaptcha", true},
		{"hcaptcha", "hcaptcha", true},
		{"uppercase", "TURNSTILE", true},
		{"with whitespace", "  recaptcha  ", true},
		{"invalid", "invalid-provider", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCaptchaProvider(tt.input)
			if result.Valid != tt.valid {
				t.Errorf("ValidateCaptchaProvider(%q) = %v, want %v", tt.input, result.Valid, tt.valid)
			}
		})
	}
}

func TestSanitizeForShell(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"plain text", "hello world", "hello world"},
		{"with semicolon", "hello; rm -rf /", "hello rm -rf /"},
		{"with pipe", "cat file | grep password", "cat file  grep password"},
		{"with backticks", "echo `whoami`", "echo whoami"},
		{"with dollar sign", "echo $HOME", "echo HOME"},
		{"with newline", "hello\nworld", "helloworld"},
		{"with null byte", "hello\x00world", "helloworld"},
		{"with quotes", "hello'world\"test", "helloworldtest"},
		{"empty", "", ""},
		{"only dangerous chars", ";|&$`", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizeForShell(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeForShell(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsSafeForShell(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"plain text", "hello world", true},
		{"with hyphen", "hello-world", true},
		{"with underscore", "hello_world", true},
		{"with numbers", "test123", true},
		{"with semicolon", "hello; world", false},
		{"with pipe", "hello | world", false},
		{"with dollar", "hello$world", false},
		{"with backtick", "hello`world", false},
		{"with newline", "hello\nworld", false},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSafeForShell(tt.input)
			if result != tt.expected {
				t.Errorf("IsSafeForShell(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidateNonEmpty(t *testing.T) {
	tests := []struct {
		name  string
		value string
		field string
		valid bool
	}{
		{"non-empty", "value", "field", true},
		{"with whitespace", "  value  ", "field", true},
		{"empty", "", "field", false},
		{"only whitespace", "   ", "field", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateNonEmpty(tt.value, tt.field)
			if result.Valid != tt.valid {
				t.Errorf("ValidateNonEmpty(%q, %q) = %v, want %v", tt.value, tt.field, result.Valid, tt.valid)
			}
		})
	}
}

func TestValidateDuration(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"hours", "4h", true},
		{"minutes", "30m", true},
		{"seconds", "60s", true},
		{"days", "7d", true},
		{"invalid format", "4 hours", false},
		{"no unit", "30", false},
		{"invalid unit", "4x", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateDuration(tt.input)
			if result.Valid != tt.valid {
				t.Errorf("ValidateDuration(%q) = %v, want %v", tt.input, result.Valid, tt.valid)
			}
		})
	}
}

func TestValidateContainerName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"simple", "mycontainer", true},
		{"with hyphen", "my-container", true},
		{"with underscore", "my_container", true},
		{"with dot", "my.container", true},
		{"with numbers", "container123", true},
		{"starts with number", "123container", true},
		{"starts with special", "-container", false},
		{"with spaces", "my container", false},
		{"with special chars", "my$container", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateContainerName(tt.input)
			if result.Valid != tt.valid {
				t.Errorf("ValidateContainerName(%q) = %v, want %v", tt.input, result.Valid, tt.valid)
			}
		})
	}
}

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"absolute path", "/etc/crowdsec/config.yaml", true},
		{"relative with dot", "./config/file.yaml", true},
		{"with null byte", "/etc/config\x00.yaml", false},
		{"empty", "", false},
		{"relative without dot", "config/file.yaml", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidatePath(tt.input)
			if result.Valid != tt.valid {
				t.Errorf("ValidatePath(%q) = %v, want %v", tt.input, result.Valid, tt.valid)
			}
		})
	}
}

func TestValidateYAMLFilePath(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"yaml extension", "/etc/config.yaml", true},
		{"yml extension", "/etc/config.yml", true},
		{"wrong extension", "/etc/config.json", false},
		{"no extension", "/etc/config", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateYAMLFilePath(tt.input)
			if result.Valid != tt.valid {
				t.Errorf("ValidateYAMLFilePath(%q) = %v, want %v", tt.input, result.Valid, tt.valid)
			}
		})
	}
}

func TestValidateHostPath(t *testing.T) {
	// Create a temp directory and file for testing
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "testfile.txt")
	if err := os.WriteFile(tempFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	tests := []struct {
		name         string
		path         string
		expectedType string
		exists       bool
	}{
		{"existing directory", tempDir, "directory", true},
		{"existing file", tempFile, "file", true},
		{"non-existing path", filepath.Join(tempDir, "nonexistent"), "file", false},
		{"empty path", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateHostPath(tt.path, tt.expectedType)
			if result.Exists != tt.exists {
				t.Errorf("ValidateHostPath(%q, %q).Exists = %v, want %v", tt.path, tt.expectedType, result.Exists, tt.exists)
			}
		})
	}
}

func TestEnsureDirectoryExists(t *testing.T) {
	tempDir := t.TempDir()
	newDir := filepath.Join(tempDir, "new", "nested", "dir")

	// Test creating new directory
	err := EnsureDirectoryExists(newDir)
	if err != nil {
		t.Errorf("EnsureDirectoryExists(%q) returned error: %v", newDir, err)
	}

	// Verify it exists
	info, err := os.Stat(newDir)
	if err != nil {
		t.Errorf("Directory was not created: %v", err)
	}
	if !info.IsDir() {
		t.Error("Created path is not a directory")
	}

	// Test with empty path
	err = EnsureDirectoryExists("")
	if err == nil {
		t.Error("EnsureDirectoryExists('') should return an error")
	}
}

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"simple path", "/etc/config.yaml", "/etc/config.yaml"},
		{"with dangerous chars", "/etc/config;rm -rf /", "/etc/configrm -rf /"},
		{"with null byte", "/etc/config\x00.yaml", "/etc/config.yaml"},
		{"with newline", "/etc/config\n.yaml", "/etc/config.yaml"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SanitizePath(tt.input)
			// Use filepath.Clean on expected for comparison
			expected := filepath.Clean(tt.expected)
			if tt.expected == "" {
				expected = ""
			}
			if result != expected {
				t.Errorf("SanitizePath(%q) = %q, want %q", tt.input, result, expected)
			}
		})
	}
}
