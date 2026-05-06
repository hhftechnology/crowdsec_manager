package handlers

import (
	"errors"
	"testing"
)

func TestNormalizeDuration(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantValue string
		wantOK    bool
	}{
		// Permanent / omitted flag cases — all collapse to "" + ok.
		{"empty string", "", "", true},
		{"plain zero", "0", "", true},
		{"zero seconds", "0s", "", true},
		{"literal permanent", "permanent", "", true},
		{"literal Permanent (capitalised)", "Permanent", "", true},
		{"literal never", "never", "", true},
		{"literal forever", "forever", "", true},
		{"whitespace permanent", "  permanent  ", "", true},

		// Valid Go-style durations passthrough as-is.
		{"hours", "4h", "4h", true},
		{"minutes", "30m", "30m", true},
		{"seconds", "45s", "45s", true},
		{"compound", "2h45m", "2h45m", true},

		// Days / weeks are not native Go duration units; we translate.
		{"days", "30d", "720h", true},
		{"single day", "1d", "24h", true},
		{"weeks", "1w", "168h", true},
		{"two weeks", "2w", "336h", true},

		// Invalid inputs.
		{"garbage", "garbage", "", false},
		{"negative duration", "-4h", "", false},
		{"trailing junk", "4hxyz", "", false},
		{"only unit", "h", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NormalizeDuration(tt.input)
			if got != tt.wantValue {
				t.Errorf("NormalizeDuration(%q) value = %q, want %q", tt.input, got, tt.wantValue)
			}
			if ok != tt.wantOK {
				t.Errorf("NormalizeDuration(%q) ok = %v, want %v", tt.input, ok, tt.wantOK)
			}
		})
	}
}

func TestValidateAddDecisionRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     AddDecisionRequest
		wantErr error
	}{
		{
			name:    "ip only — valid",
			req:     AddDecisionRequest{IP: "1.2.3.4"},
			wantErr: nil,
		},
		{
			name:    "range only — valid",
			req:     AddDecisionRequest{Range: "10.0.0.0/24"},
			wantErr: nil,
		},
		{
			name:    "value only — valid",
			req:     AddDecisionRequest{Value: "user@example.com", Scope: "session"},
			wantErr: nil,
		},
		{
			name:    "ip + scope ip + value — mixed selector rejected",
			req:     AddDecisionRequest{IP: "1.2.3.4", Scope: "ip", Value: "1.2.3.4"},
			wantErr: ErrMixedSelector,
		},
		{
			name:    "empty — at least one selector required",
			req:     AddDecisionRequest{},
			wantErr: ErrNoSelector,
		},
		{
			name:    "ip + range together — mutually exclusive",
			req:     AddDecisionRequest{IP: "1.2.3.4", Range: "10.0.0.0/24"},
			wantErr: ErrIPAndRange,
		},
		{
			name:    "type/scope/duration without value — incomplete selector",
			req:     AddDecisionRequest{Type: "ban", Scope: "ip", Duration: "4h"},
			wantErr: ErrIncompleteSelector,
		},
		{
			name:    "value without scope — incomplete selector",
			req:     AddDecisionRequest{Value: "1.2.3.4"},
			wantErr: ErrIncompleteSelector,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAddDecisionRequest(&tt.req)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("ValidateAddDecisionRequest() unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ValidateAddDecisionRequest() err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
