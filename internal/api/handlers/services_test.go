package handlers

import "testing"

func TestPastTenseServiceAction(t *testing.T) {
	tests := []struct {
		name   string
		action string
		want   string
	}{
		{name: "stop", action: "stop", want: "stopped"},
		{name: "start", action: "start", want: "started"},
		{name: "restart", action: "restart", want: "restarted"},
		{name: "fallback", action: "scale", want: "scaleed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pastTenseServiceAction(tt.action)
			if got != tt.want {
				t.Fatalf("pastTenseServiceAction(%q) = %q, want %q", tt.action, got, tt.want)
			}
		})
	}
}
