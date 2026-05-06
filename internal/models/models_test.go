package models

import (
	"encoding/json"
	"testing"
)

// TestResponseDetailsField verifies the Details field is present and serialized correctly.
func TestResponseDetailsField(t *testing.T) {
	r := Response{
		Success: false,
		Error:   "something went wrong",
		Details: "raw stderr output here",
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if m["details"] != "raw stderr output here" {
		t.Errorf("expected details field, got: %v", m["details"])
	}
	if m["error"] != "something went wrong" {
		t.Errorf("expected error field, got: %v", m["error"])
	}
}

// TestResponseDetailsOmitEmpty verifies Details is omitted when empty.
func TestResponseDetailsOmitEmpty(t *testing.T) {
	r := Response{Success: true, Message: "ok"}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if _, ok := m["details"]; ok {
		t.Errorf("details should be omitted when empty, but it was present")
	}
}
