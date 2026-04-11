package handlers

import (
	"testing"

	"crowdsec-manager/internal/logger"
)

func TestTruncateString(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{
			name:   "shorter than max",
			input:  "hello",
			maxLen: 10,
			want:   "hello",
		},
		{
			name:   "exact length",
			input:  "hello",
			maxLen: 5,
			want:   "hello",
		},
		{
			name:   "longer than max",
			input:  "hello world",
			maxLen: 5,
			want:   "hello... (truncated)",
		},
		{
			name:   "empty string",
			input:  "",
			maxLen: 10,
			want:   "",
		},
		{
			name:   "maxLen zero",
			input:  "abc",
			maxLen: 0,
			want:   "... (truncated)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateString(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateString(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestParseDecisionNode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantID   int64
		wantType string
		wantVal  string
		wantSim  bool
	}{
		{
			name:     "full decision",
			input:    `{"id":42,"origin":"crowdsec","type":"ban","scope":"Ip","value":"1.2.3.4","duration":"4h","scenario":"crowdsecurity/ssh-bf","simulated":false,"created_at":"2024-01-01T00:00:00Z"}`,
			wantID:   42,
			wantType: "ban",
			wantVal:  "1.2.3.4",
			wantSim:  false,
		},
		{
			name:     "simulated decision",
			input:    `{"id":99,"type":"captcha","value":"10.0.0.1","simulated":true}`,
			wantID:   99,
			wantType: "captcha",
			wantVal:  "10.0.0.1",
			wantSim:  true,
		},
		{
			name:     "empty input",
			input:    `{}`,
			wantID:   0,
			wantType: "",
			wantVal:  "",
			wantSim:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := parseDecisionNode([]byte(tt.input))
			if d.ID != tt.wantID {
				t.Errorf("ID: got %d, want %d", d.ID, tt.wantID)
			}
			if d.Type != tt.wantType {
				t.Errorf("Type: got %q, want %q", d.Type, tt.wantType)
			}
			if d.Value != tt.wantVal {
				t.Errorf("Value: got %q, want %q", d.Value, tt.wantVal)
			}
			if d.Simulated != tt.wantSim {
				t.Errorf("Simulated: got %v, want %v", d.Simulated, tt.wantSim)
			}
		})
	}
}

func TestAppendCLIFlags(t *testing.T) {
	tests := []struct {
		name      string
		cmd       []string
		flags     []CLIFlag
		wantCmd   []string
		wantCount int
	}{
		{
			name:      "no flags",
			cmd:       []string{"cscli", "decisions", "list"},
			flags:     []CLIFlag{},
			wantCmd:   []string{"cscli", "decisions", "list"},
			wantCount: 0,
		},
		{
			name: "one populated flag",
			cmd:  []string{"cscli"},
			flags: []CLIFlag{
				{Flag: "--type", Value: "ban"},
			},
			wantCmd:   []string{"cscli", "--type", "ban"},
			wantCount: 1,
		},
		{
			name: "empty value skipped",
			cmd:  []string{"cscli"},
			flags: []CLIFlag{
				{Flag: "--type", Value: ""},
				{Flag: "--scope", Value: "Ip"},
			},
			wantCmd:   []string{"cscli", "--scope", "Ip"},
			wantCount: 1,
		},
		{
			name: "multiple flags",
			cmd:  []string{"cscli", "decisions", "list"},
			flags: []CLIFlag{
				{Flag: "--type", Value: "ban"},
				{Flag: "--scope", Value: "Ip"},
				{Flag: "--value", Value: "1.2.3.4"},
			},
			wantCmd:   []string{"cscli", "decisions", "list", "--type", "ban", "--scope", "Ip", "--value", "1.2.3.4"},
			wantCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCmd, gotCount := appendCLIFlags(tt.cmd, tt.flags)
			if gotCount != tt.wantCount {
				t.Errorf("count: got %d, want %d", gotCount, tt.wantCount)
			}
			if len(gotCmd) != len(tt.wantCmd) {
				t.Fatalf("cmd length: got %d, want %d (got %v)", len(gotCmd), len(tt.wantCmd), gotCmd)
			}
			for i, v := range tt.wantCmd {
				if gotCmd[i] != v {
					t.Errorf("cmd[%d]: got %q, want %q", i, gotCmd[i], v)
				}
			}
		})
	}
}

func TestParseDecisionsFromOutput(t *testing.T) {
	logger.Init("info", "")

	tests := []struct {
		name      string
		input     string
		wantCount int
		wantErr   bool
		checkFunc func(t *testing.T, decisions []interface{ GetValue() string })
	}{
		{
			name:      "no json input",
			input:     "No JSON here",
			wantCount: 0,
			wantErr:   true,
		},
		{
			// "null" contains no JSON array/object characters — parseCLIJSONOutput returns error.
			// Callers guard against "null" before calling ParseDecisionsFromOutput.
			name:      "null output",
			input:     "null",
			wantCount: 0,
			wantErr:   true,
		},
		{
			name:      "empty array",
			input:     "[]",
			wantCount: 0,
			wantErr:   false,
		},
		{
			name: "flat decision array (cscli decisions add format)",
			input: `[{"id":1,"type":"ban","value":"1.2.3.4","scope":"Ip","origin":"cscli","duration":"4h","scenario":"manual"}]`,
			wantCount: 1,
			wantErr:   false,
		},
		{
			name: "nested decisions in alerts",
			input: `[{"id":10,"created_at":"2024-01-01T00:00:00Z","decisions":[{"id":1,"type":"ban","value":"1.2.3.4","scope":"Ip"},{"id":2,"type":"ban","value":"5.6.7.8","scope":"Ip"}]}]`,
			wantCount: 2,
			wantErr:   false,
		},
		{
			name: "multiple alerts with decisions",
			input: `[{"id":1,"decisions":[{"id":10,"type":"ban","value":"1.1.1.1"}]},{"id":2,"decisions":[{"id":11,"type":"captcha","value":"2.2.2.2"}]}]`,
			wantCount: 2,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decisions, err := ParseDecisionsFromOutput(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (decisions: %v)", decisions)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(decisions) != tt.wantCount {
				t.Errorf("decision count: got %d, want %d (decisions: %+v)", len(decisions), tt.wantCount, decisions)
			}
		})
	}
}

func TestParseDecisionsFromOutput_AlertIDPropagation(t *testing.T) {
	logger.Init("info", "")
	input := `[{"id":42,"created_at":"2024-06-01T12:00:00Z","decisions":[{"id":100,"type":"ban","value":"10.0.0.1"}]}]`
	decisions, err := ParseDecisionsFromOutput(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(decisions))
	}
	if decisions[0].AlertID != 42 {
		t.Errorf("AlertID: got %d, want 42", decisions[0].AlertID)
	}
	if decisions[0].CreatedAt != "2024-06-01T12:00:00Z" {
		t.Errorf("CreatedAt inherited from alert: got %q, want 2024-06-01T12:00:00Z", decisions[0].CreatedAt)
	}
}

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