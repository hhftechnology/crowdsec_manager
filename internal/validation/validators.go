// Package validation provides centralized input validation utilities
// for the CrowdSec Manager application. All handlers should use these
// validators to ensure consistent security and input handling.
package validation

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// ValidationResult represents the result of a validation check
type ValidationResult struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message,omitempty"`
	Value   string `json:"value,omitempty"` // Normalized/sanitized value
}

// Valid constants for common validation messages
const (
	MsgInvalidIP           = "invalid IP address format"
	MsgInvalidCIDR         = "invalid CIDR notation"
	MsgInvalidIPOrCIDR     = "value must be a valid IP address or CIDR range"
	MsgInvalidURL          = "invalid URL format"
	MsgInvalidWebhookURL   = "invalid webhook URL"
	MsgInvalidDiscordURL   = "URL must be a valid Discord webhook URL (https://discord.com/api/webhooks/...)"
	MsgInvalidProvider     = "invalid captcha provider"
	MsgEmptyValue          = "value cannot be empty"
	MsgDangerousCharacters = "value contains potentially dangerous characters"
)

// Supported captcha providers
var validCaptchaProviders = map[string]bool{
	"turnstile": true,
	"recaptcha": true,
	"hcaptcha":  true,
}

// shellDangerousChars are characters that could be used for shell injection
var shellDangerousChars = regexp.MustCompile(`[;&|$` + "`" + `\\<>(){}[\]!*?#~]`)

// shellDangerousPatterns are patterns that could be used for command injection
var shellDangerousPatterns = []string{
	"$(", "${", "`", "&&", "||", ";", "|", ">", "<", ">>", "<<",
	"\n", "\r", "\x00",
}

// ValidateIP validates that a string is a valid IPv4 or IPv6 address
func ValidateIP(ip string) ValidationResult {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ValidationResult{Valid: false, Message: MsgEmptyValue}
	}

	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ValidationResult{Valid: false, Message: MsgInvalidIP, Value: ip}
	}

	// Return normalized IP string
	return ValidationResult{Valid: true, Value: parsed.String()}
}

// ValidateCIDR validates that a string is a valid CIDR notation
func ValidateCIDR(cidr string) ValidationResult {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" {
		return ValidationResult{Valid: false, Message: MsgEmptyValue}
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return ValidationResult{Valid: false, Message: MsgInvalidCIDR, Value: cidr}
	}

	// Return normalized CIDR string
	return ValidationResult{Valid: true, Value: network.String()}
}

// ValidateIPOrCIDR validates that a string is either a valid IP or CIDR
func ValidateIPOrCIDR(value string) ValidationResult {
	value = strings.TrimSpace(value)
	if value == "" {
		return ValidationResult{Valid: false, Message: MsgEmptyValue}
	}

	// Try as CIDR first (includes single IPs like 192.168.1.1/32)
	if strings.Contains(value, "/") {
		return ValidateCIDR(value)
	}

	// Try as plain IP
	return ValidateIP(value)
}

// ValidateWebhookURL validates that a URL is a valid webhook URL
// It checks for HTTPS and proper URL structure
func ValidateWebhookURL(rawURL string) ValidationResult {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ValidationResult{Valid: false, Message: MsgEmptyValue}
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ValidationResult{Valid: false, Message: MsgInvalidURL, Value: rawURL}
	}

	// Must be HTTPS for webhooks
	if parsed.Scheme != "https" {
		return ValidationResult{
			Valid:   false,
			Message: "webhook URL must use HTTPS",
			Value:   rawURL,
		}
	}

	// Must have a host
	if parsed.Host == "" {
		return ValidationResult{Valid: false, Message: MsgInvalidURL, Value: rawURL}
	}

	return ValidationResult{Valid: true, Value: parsed.String()}
}

// ValidateDiscordWebhookURL validates that a URL is a valid Discord webhook URL
func ValidateDiscordWebhookURL(rawURL string) ValidationResult {
	// First do basic webhook validation
	result := ValidateWebhookURL(rawURL)
	if !result.Valid {
		return result
	}

	parsed, _ := url.Parse(rawURL)

	// Must be discord.com or discordapp.com
	host := strings.ToLower(parsed.Host)
	if host != "discord.com" && host != "discordapp.com" {
		return ValidationResult{
			Valid:   false,
			Message: MsgInvalidDiscordURL,
			Value:   rawURL,
		}
	}

	// Path must start with /api/webhooks/
	if !strings.HasPrefix(parsed.Path, "/api/webhooks/") {
		return ValidationResult{
			Valid:   false,
			Message: MsgInvalidDiscordURL,
			Value:   rawURL,
		}
	}

	// Extract webhook ID and token from path
	parts := strings.Split(strings.TrimPrefix(parsed.Path, "/api/webhooks/"), "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ValidationResult{
			Valid:   false,
			Message: "Discord webhook URL must contain webhook ID and token",
			Value:   rawURL,
		}
	}

	return ValidationResult{Valid: true, Value: parsed.String()}
}

// ValidateCaptchaProvider validates that a provider name is supported
func ValidateCaptchaProvider(provider string) ValidationResult {
	provider = strings.TrimSpace(strings.ToLower(provider))
	if provider == "" {
		return ValidationResult{Valid: false, Message: MsgEmptyValue}
	}

	if !validCaptchaProviders[provider] {
		validList := make([]string, 0, len(validCaptchaProviders))
		for k := range validCaptchaProviders {
			validList = append(validList, k)
		}
		return ValidationResult{
			Valid:   false,
			Message: fmt.Sprintf("%s: must be one of [%s]", MsgInvalidProvider, strings.Join(validList, ", ")),
			Value:   provider,
		}
	}

	return ValidationResult{Valid: true, Value: provider}
}

// SanitizeForShell sanitizes a string to be safely used in shell commands
// CRITICAL: This function is essential for preventing shell injection attacks
// It removes or escapes dangerous characters and patterns
func SanitizeForShell(input string) string {
	if input == "" {
		return ""
	}

	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Remove newlines and carriage returns
	input = strings.ReplaceAll(input, "\n", "")
	input = strings.ReplaceAll(input, "\r", "")

	// Replace dangerous shell metacharacters with escaped versions or remove them
	// For maximum safety, we'll remove rather than escape
	result := shellDangerousChars.ReplaceAllString(input, "")

	// Trim whitespace
	result = strings.TrimSpace(result)

	return result
}

// IsSafeForShell checks if a string is safe to use in shell commands without modification
// Returns true if the string contains no dangerous characters
func IsSafeForShell(input string) bool {
	if input == "" {
		return true
	}

	// Check for dangerous characters
	if shellDangerousChars.MatchString(input) {
		return false
	}

	// Check for dangerous patterns
	for _, pattern := range shellDangerousPatterns {
		if strings.Contains(input, pattern) {
			return false
		}
	}

	// Check for non-printable characters (except space)
	for _, r := range input {
		if r < 32 && r != 9 { // Allow tab (9) but reject other control chars
			return false
		}
		if r == 127 { // DEL character
			return false
		}
	}

	return true
}

// ValidateNonEmpty validates that a string is not empty after trimming
func ValidateNonEmpty(value, fieldName string) ValidationResult {
	value = strings.TrimSpace(value)
	if value == "" {
		return ValidationResult{
			Valid:   false,
			Message: fmt.Sprintf("%s cannot be empty", fieldName),
		}
	}
	return ValidationResult{Valid: true, Value: value}
}

// ValidateAPIKey validates that an API key has a reasonable format
// This is a basic validation - specific APIs may have stricter requirements
func ValidateAPIKey(key string) ValidationResult {
	key = strings.TrimSpace(key)
	if key == "" {
		return ValidationResult{Valid: false, Message: MsgEmptyValue}
	}

	// API keys typically contain only alphanumeric characters, hyphens, and underscores
	for _, r := range key {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return ValidationResult{
				Valid:   false,
				Message: "API key contains invalid characters",
				Value:   key,
			}
		}
	}

	// Most API keys are at least 16 characters
	if len(key) < 8 {
		return ValidationResult{
			Valid:   false,
			Message: "API key appears too short",
			Value:   key,
		}
	}

	return ValidationResult{Valid: true, Value: key}
}

// ValidateDuration validates a duration string (e.g., "4h", "30m", "1d")
func ValidateDuration(duration string) ValidationResult {
	duration = strings.TrimSpace(duration)
	if duration == "" {
		return ValidationResult{Valid: false, Message: MsgEmptyValue}
	}

	// Valid duration patterns: number followed by unit (s, m, h, d)
	durationPattern := regexp.MustCompile(`^\d+[smhd]$`)
	if !durationPattern.MatchString(duration) {
		return ValidationResult{
			Valid:   false,
			Message: "invalid duration format (use format like 4h, 30m, 1d)",
			Value:   duration,
		}
	}

	return ValidationResult{Valid: true, Value: duration}
}

// ValidateContainerName validates a Docker container name
func ValidateContainerName(name string) ValidationResult {
	name = strings.TrimSpace(name)
	if name == "" {
		return ValidationResult{Valid: false, Message: MsgEmptyValue}
	}

	// Docker container names must match [a-zA-Z0-9][a-zA-Z0-9_.-]*
	containerNamePattern := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
	if !containerNamePattern.MatchString(name) {
		return ValidationResult{
			Valid:   false,
			Message: "invalid container name format",
			Value:   name,
		}
	}

	return ValidationResult{Valid: true, Value: name}
}
