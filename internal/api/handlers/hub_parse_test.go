package handlers

import (
	"testing"
)

func TestParseHubJSONOutput(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError bool
		assert    func(t *testing.T, parsed interface{})
	}{
		{
			name:  "parses clean object",
			input: `{"collections":[{"name":"a"}]}`,
			assert: func(t *testing.T, parsed interface{}) {
				t.Helper()
				record, ok := parsed.(map[string]interface{})
				if !ok {
					t.Fatalf("expected object, got %T", parsed)
				}
				items, ok := record["collections"].([]interface{})
				if !ok || len(items) != 1 {
					t.Fatalf("expected one collection item, got %#v", record["collections"])
				}
			},
		},
		{
			name: "parses object with preamble and trailing logs",
			input: "Loaded: 1 parser\\nUnmanaged items: 0\\n" +
				`{"scenarios":[{"name":"test/scenario"}]}` +
				"\\noperation completed",
			assert: func(t *testing.T, parsed interface{}) {
				t.Helper()
				record, ok := parsed.(map[string]interface{})
				if !ok {
					t.Fatalf("expected object, got %T", parsed)
				}
				items, ok := record["scenarios"].([]interface{})
				if !ok || len(items) != 1 {
					t.Fatalf("expected one scenario item, got %#v", record["scenarios"])
				}
			},
		},
		{
			name:  "parses list payload",
			input: "Info line\\n" + `[{"name":"crowdsecurity/test"}]`,
			assert: func(t *testing.T, parsed interface{}) {
				t.Helper()
				items, ok := parsed.([]interface{})
				if !ok || len(items) != 1 {
					t.Fatalf("expected one array item, got %#v", parsed)
				}
			},
		},
		{
			name:      "fails without json",
			input:     "Loaded: 1 parser\\nNo JSON output",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := parseHubJSONOutput(tt.input)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error, got parsed=%#v", parsed)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.assert != nil {
				tt.assert(t, parsed)
			}
		})
	}
}

func TestFirstJSONStartIndex(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{name: "object first", input: "prefix {\"k\":1}", want: 7},
		{name: "array first", input: "prefix [1,2]", want: 7},
		{name: "none", input: "no json", want: -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstJSONStartIndex(tt.input); got != tt.want {
				t.Fatalf("got %d want %d", got, tt.want)
			}
		})
	}
}
