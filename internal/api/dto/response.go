// Package dto provides standardized request/response types for all API handlers.
// All handlers should use these types to ensure consistent JSON shapes for the frontend.
package dto

import "net/http"

// Response is the standard API response envelope.
// All API endpoints must return responses in this shape.
type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// Success creates a successful response with data.
func Success(data interface{}) Response {
	return Response{Success: true, Data: data}
}

// SuccessWithMessage creates a successful response with data and a message.
func SuccessWithMessage(data interface{}, message string) Response {
	return Response{Success: true, Data: data, Message: message}
}

// SuccessMessage creates a successful response with only a message (no data).
func SuccessMessage(message string) Response {
	return Response{Success: true, Message: message}
}

// Err creates an error response from an error value.
func Err(err error) Response {
	return Response{Success: false, Error: err.Error()}
}

// ErrMsg creates an error response from a string message.
func ErrMsg(message string) Response {
	return Response{Success: false, Error: message}
}

// ErrWithMessage creates an error response with both an error and a message.
func ErrWithMessage(err error, message string) Response {
	return Response{Success: false, Error: err.Error(), Message: message}
}

// StatusForHealth returns the appropriate HTTP status code for a health status string.
// "unhealthy" -> 503 Service Unavailable, everything else -> 200 OK.
func StatusForHealth(status string) int {
	if status == "unhealthy" {
		return http.StatusServiceUnavailable
	}
	return http.StatusOK
}
