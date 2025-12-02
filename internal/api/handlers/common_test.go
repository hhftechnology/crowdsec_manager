package handlers

import (
	"testing"
)

// MockDockerClient is a mock implementation of the docker client interface
type MockDockerClient struct {
	Output string
	Err    error
}

func (m *MockDockerClient) ExecCommand(containerName string, cmd []string) (string, error) {
	return m.Output, m.Err
}

func TestGetConsoleStatusHelper_Mapping(t *testing.T) {
	tests := []struct {
		name           string
		output         string
		expectEnrolled bool
		expectValidated bool
	}{
		{
			name:           "Standard JSON",
			output:         `{"enrolled": true, "validated": true}`,
			expectEnrolled: true,
			expectValidated: true,
		},
		{
			name:           "Manual only (User case)",
			output:         `{"manual": true, "console_management": false}`,
			expectEnrolled: true,
			expectValidated: false,
		},
		{
			name:           "Manual and Console Management",
			output:         `{"manual": true, "console_management": true}`,
			expectEnrolled: true,
			expectValidated: true,
		},
		{
			name:           "Not enrolled",
			output:         `{"enrolled": false, "manual": false}`,
			expectEnrolled: false,
			expectValidated: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockDockerClient{Output: tt.output}
			status, err := GetConsoleStatusHelper(mockClient, "crowdsec")
			
			t.Logf("Raw Output: %s", tt.output)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			t.Logf("Parsed Status: %+v", status)

			if status.Enrolled != tt.expectEnrolled {
				t.Errorf("Enrolled: got %v, want %v. Status: %+v", status.Enrolled, tt.expectEnrolled, status)
			}
			if status.Validated != tt.expectValidated {
				t.Errorf("Validated: got %v, want %v. Status: %+v", status.Validated, tt.expectValidated, status)
			}
		})
	}
}
