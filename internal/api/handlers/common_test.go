package handlers

import (
	"testing"

	"crowdsec-manager/internal/logger"
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
	// Initialize logger for tests
	logger.Init("info", "")

	tests := []struct {
		name            string
		output          string
		expectEnrolled  bool
		expectValidated bool
		expectApproved  bool
		expectPhase     string
	}{
		{
			name:            "Standard JSON",
			output:          `{"enrolled": true, "validated": true}`,
			expectEnrolled:  true,
			expectValidated: true,
			expectApproved:  true,
			expectPhase:     "approved",
		},
		{
			name:            "Manual only (not approved)",
			output:          `{"manual": true, "console_management": false}`,
			expectEnrolled:  false,
			expectValidated: false,
			expectApproved:  false,
			expectPhase:     "pending_approval",
		},
		{
			name:            "Manual and Console Management",
			output:          `{"manual": true, "console_management": true}`,
			expectEnrolled:  true,
			expectValidated: true,
			expectApproved:  true,
			expectPhase:     "management_enabled",
		},
		{
			name:            "Not enrolled",
			output:          `{"enrolled": false, "manual": false}`,
			expectEnrolled:  false,
			expectValidated: false,
			expectApproved:  false,
			expectPhase:     "not_enrolled",
		},
		{
			name:            "User pre-enrollment output",
			output:          `{"console_management": false, "context": false, "custom": true, "manual": false, "tainted": true}`,
			expectEnrolled:  false,
			expectValidated: false,
			expectApproved:  false,
			expectPhase:     "not_enrolled",
		},
		{
			name:            "User post-approval output",
			output:          `{"console_management": false, "context": true, "custom": true, "manual": true, "tainted": true}`,
			expectEnrolled:  true,
			expectValidated: true,
			expectApproved:  true,
			expectPhase:     "approved",
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
			if status.Approved != tt.expectApproved {
				t.Errorf("Approved: got %v, want %v. Status: %+v", status.Approved, tt.expectApproved, status)
			}
			if status.Phase != tt.expectPhase {
				t.Errorf("Phase: got %q, want %q. Status: %+v", status.Phase, tt.expectPhase, status)
			}
		})
	}
}
