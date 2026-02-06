package dto

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func TestSuccess(t *testing.T) {
	resp := Success(map[string]string{"key": "value"})
	if !resp.Success {
		t.Error("expected Success to be true")
	}
	if resp.Error != "" {
		t.Error("expected Error to be empty")
	}
	if resp.Data == nil {
		t.Error("expected Data to be set")
	}
}

func TestSuccessMessage(t *testing.T) {
	resp := SuccessMessage("done")
	if !resp.Success {
		t.Error("expected Success to be true")
	}
	if resp.Message != "done" {
		t.Errorf("expected message 'done', got %q", resp.Message)
	}
	if resp.Data != nil {
		t.Error("expected Data to be nil")
	}
}

func TestSuccessWithMessage(t *testing.T) {
	resp := SuccessWithMessage("data", "ok")
	if !resp.Success {
		t.Error("expected Success to be true")
	}
	if resp.Message != "ok" {
		t.Errorf("expected message 'ok', got %q", resp.Message)
	}
}

func TestErr(t *testing.T) {
	resp := Err(errors.New("something failed"))
	if resp.Success {
		t.Error("expected Success to be false")
	}
	if resp.Error != "something failed" {
		t.Errorf("expected error 'something failed', got %q", resp.Error)
	}
}

func TestErrMsg(t *testing.T) {
	resp := ErrMsg("bad request")
	if resp.Success {
		t.Error("expected Success to be false")
	}
	if resp.Error != "bad request" {
		t.Errorf("expected error 'bad request', got %q", resp.Error)
	}
}

func TestStatusForHealth(t *testing.T) {
	tests := []struct {
		status   string
		expected int
	}{
		{"unhealthy", http.StatusServiceUnavailable},
		{"healthy", http.StatusOK},
		{"degraded", http.StatusOK},
		{"", http.StatusOK},
	}

	for _, tt := range tests {
		got := StatusForHealth(tt.status)
		if got != tt.expected {
			t.Errorf("StatusForHealth(%q) = %d, want %d", tt.status, got, tt.expected)
		}
	}
}

func TestResponseJSONShape(t *testing.T) {
	// Verify the JSON shape matches frontend ApiResponse<T> contract
	resp := SuccessWithMessage(map[string]int{"count": 5}, "fetched")
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// success field must always be present
	if _, ok := parsed["success"]; !ok {
		t.Error("missing 'success' field in JSON")
	}

	// message should be present when set
	if _, ok := parsed["message"]; !ok {
		t.Error("missing 'message' field in JSON")
	}

	// data should be present when set
	if _, ok := parsed["data"]; !ok {
		t.Error("missing 'data' field in JSON")
	}

	// error should be omitted when empty
	if _, ok := parsed["error"]; ok {
		t.Error("'error' field should be omitted when empty")
	}
}

func TestErrorResponseJSONShape(t *testing.T) {
	resp := Err(errors.New("not found"))
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// success must be false
	if parsed["success"] != false {
		t.Error("expected success to be false")
	}

	// error must be present
	if _, ok := parsed["error"]; !ok {
		t.Error("missing 'error' field in error response")
	}

	// data should be omitted
	if _, ok := parsed["data"]; ok {
		t.Error("'data' field should be omitted in error response")
	}
}
