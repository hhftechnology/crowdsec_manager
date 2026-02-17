package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// Response is the standardized API envelope for all JSON responses.
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Success creates a successful response with data.
func Success(data any) Response {
	return Response{Success: true, Data: data}
}

// SuccessWithMessage creates a successful response with data and a message.
func SuccessWithMessage(data any, msg string) Response {
	return Response{Success: true, Data: data, Message: msg}
}

// SuccessMessage creates a successful response with only a message.
func SuccessMessage(msg string) Response {
	return Response{Success: true, Message: msg}
}

// Err creates an error response from an error value.
func Err(err error) Response {
	return Response{Success: false, Error: err.Error()}
}

// ErrMsg creates an error response from a string.
func ErrMsg(msg string) Response {
	return Response{Success: false, Error: msg}
}

// JSON writes a Response as JSON with the given HTTP status code.
func JSON(w http.ResponseWriter, status int, resp Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}
