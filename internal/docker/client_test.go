package docker

import (
	"testing"
)

func TestStripControlCharacters(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "No control characters",
			input:    "Hello World",
			expected: "Hello World",
		},
		{
			name:     "ANSI color codes",
			input:    "\x1b[31mRed\x1b[0m Text",
			expected: "Red Text",
		},
		{
			name:     "Complex ANSI codes",
			input:    "\x1b[1;31mBold Red\x1b[0m",
			expected: "Bold Red",
		},
		{
			name:     "JSON with ANSI",
			input:    "\x1b[32m{\"enrolled\": true}\x1b[0m",
			expected: "{\"enrolled\": true}",
		},
		{
			name:     "Newlines and tabs",
			input:    "Line 1\nLine 2\tTabbed",
			expected: "Line 1\nLine 2\tTabbed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripControlCharacters(tt.input)
			if result != tt.expected {
				t.Errorf("stripControlCharacters(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
