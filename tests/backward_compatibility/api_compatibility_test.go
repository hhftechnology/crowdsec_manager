package backward_compatibility

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// APICompatibilityTestSuite tests backward compatibility of API endpoints
type APICompatibilityTestSuite struct {
	client  *http.Client
	baseURL string
}

// NewAPICompatibilityTestSuite creates a new API compatibility test suite
func NewAPICompatibilityTestSuite(baseURL string) *APICompatibilityTestSuite {
	return &APICompatibilityTestSuite{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: baseURL,
	}
}

// TestLegacyAPIEndpoints tests that legacy API endpoints continue working
func TestLegacyAPIEndpoints(t *testing.T) {
	suite := NewAPICompatibilityTestSuite("http://localhost:8080")
	
	// Test legacy Traefik endpoints
	t.Run("LegacyTraefikEndpoints", func(t *testing.T) {
		suite.testLegacyTraefikEndpoints(t)
	})
	
	// Test legacy field formats
	t.Run("LegacyFieldFormats", func(t *testing.T) {
		suite.testLegacyFieldFormats(t)
	})
	
	// Test legacy request formats
	t.Run("LegacyRequestFormats", func(t *testing.T) {
		suite.testLegacyRequestFormats(t)
	})
	
	// Test legacy response formats
	t.Run("LegacyResponseFormats", func(t *testing.T) {
		suite.testLegacyResponseFormats(t)
	})
}

// testLegacyTraefikEndpoints tests legacy Traefik-specific endpoints
func (s *APICompatibilityTestSuite) testLegacyTraefikEndpoints(t *testing.T) {
	legacyEndpoints := []struct {
		name     string
		method   string
		path     string
		expected int
	}{
		{"TraefikWhitelist", "GET", "/api/traefik/whitelist", 200},
		{"TraefikWhitelistAdd", "POST", "/api/traefik/whitelist", 200},
		{"TraefikCaptcha", "GET", "/api/traefik/captcha", 200},
		{"TraefikCaptchaSetup", "POST", "/api/traefik/captcha/setup", 200},
		{"TraefikLogs", "GET", "/api/traefik/logs", 200},
		{"TraefikHealth", "GET", "/api/traefik/health", 200},
		{"TraefikIntegration", "GET", "/api/traefik/integration", 200},
	}
	
	for _, endpoint := range legacyEndpoints {
		t.Run(endpoint.name, func(t *testing.T) {
			var resp *http.Response
			var err error
			
			switch endpoint.method {
			case "GET":
				resp, err = s.client.Get(s.baseURL + endpoint.path)
			case "POST":
				// Use minimal valid payload for POST requests
				payload := map[string]interface{}{
					"ip": "192.168.1.100",
				}
				jsonPayload, _ := json.Marshal(payload)
				resp, err = s.client.Post(s.baseURL+endpoint.path, "application/json", bytes.NewBuffer(jsonPayload))
			}
			
			if err != nil {
				t.Errorf("Failed to call legacy endpoint %s: %v", endpoint.path, err)
				return
			}
			defer resp.Body.Close()
			
			if resp.StatusCode != endpoint.expected {
				t.Errorf("Legacy endpoint %s returned status %d, expected %d", endpoint.path, resp.StatusCode, endpoint.expected)
			}
			
			// Verify response contains expected legacy format
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("Failed to read response body for %s: %v", endpoint.path, err)
				return
			}
			
			// Check that response is valid JSON
			var jsonResponse interface{}
			if err := json.Unmarshal(body, &jsonResponse); err != nil {
				t.Errorf("Legacy endpoint %s returned invalid JSON: %v", endpoint.path, err)
			}
		})
	}
}

// testLegacyFieldFormats tests that legacy field names are preserved in responses
func (s *APICompatibilityTestSuite) testLegacyFieldFormats(t *testing.T) {
	testCases := []struct {
		name           string
		endpoint       string
		legacyFields   []string
		newFields      []string
	}{
		{
			name:     "ProxyInfo",
			endpoint: "/api/proxy/current",
			legacyFields: []string{
				"traefik_enabled",
				"traefik_container_name",
				"traefik_dynamic_config",
				"traefik_static_config",
				"traefik_access_log",
			},
			newFields: []string{
				"proxy_enabled",
				"proxy_type",
				"proxy_container_name",
				"proxy_config_paths",
			},
		},
		{
			name:     "WhitelistInfo",
			endpoint: "/api/whitelist",
			legacyFields: []string{
				"in_traefik",
				"add_to_traefik",
			},
			newFields: []string{
				"in_proxy",
				"add_to_proxy",
			},
		},
		{
			name:     "IntegrationInfo",
			endpoint: "/api/integration",
			legacyFields: []string{
				"traefik_integration",
				"traefik_bouncer_configured",
			},
			newFields: []string{
				"proxy_integration",
				"proxy_bouncer_configured",
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.client.Get(s.baseURL + tc.endpoint)
			if err != nil {
				t.Fatalf("Failed to call endpoint %s: %v", tc.endpoint, err)
			}
			defer resp.Body.Close()
			
			if resp.StatusCode != 200 {
				t.Fatalf("Endpoint %s returned status %d", tc.endpoint, resp.StatusCode)
			}
			
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}
			
			var response map[string]interface{}
			if err := json.Unmarshal(body, &response); err != nil {
				t.Fatalf("Failed to parse JSON response: %v", err)
			}
			
			// Check that legacy fields are present
			for _, field := range tc.legacyFields {
				if _, exists := response[field]; !exists {
					t.Errorf("Legacy field %s not found in response", field)
				}
			}
			
			// Check that new fields are also present
			for _, field := range tc.newFields {
				if _, exists := response[field]; !exists {
					t.Errorf("New field %s not found in response", field)
				}
			}
			
			// Verify field value consistency where applicable
			s.verifyFieldConsistency(t, response, tc.legacyFields, tc.newFields)
		})
	}
}

// verifyFieldConsistency checks that legacy and new fields have consistent values
func (s *APICompatibilityTestSuite) verifyFieldConsistency(t *testing.T, response map[string]interface{}, legacyFields, newFields []string) {
	// Map legacy fields to new fields for consistency checking
	fieldMappings := map[string]string{
		"traefik_enabled":        "proxy_enabled",
		"traefik_container_name": "proxy_container_name",
		"in_traefik":            "in_proxy",
		"add_to_traefik":        "add_to_proxy",
	}
	
	for legacyField, newField := range fieldMappings {
		legacyValue, legacyExists := response[legacyField]
		newValue, newExists := response[newField]
		
		if legacyExists && newExists {
			if legacyValue != newValue {
				t.Errorf("Field value mismatch: %s=%v, %s=%v", legacyField, legacyValue, newField, newValue)
			}
		}
	}
}

// testLegacyRequestFormats tests that legacy request formats are accepted
func (s *APICompatibilityTestSuite) testLegacyRequestFormats(t *testing.T) {
	testCases := []struct {
		name     string
		endpoint string
		method   string
		payload  map[string]interface{}
	}{
		{
			name:     "LegacyWhitelistAdd",
			endpoint: "/api/whitelist",
			method:   "POST",
			payload: map[string]interface{}{
				"ip":             "192.168.1.100",
				"add_to_crowdsec": true,
				"add_to_traefik":  true, // Legacy field
			},
		},
		{
			name:     "LegacyCaptchaSetup",
			endpoint: "/api/captcha/setup",
			method:   "POST",
			payload: map[string]interface{}{
				"provider":    "cloudflare",
				"site_key":    "test_site_key",
				"secret_key":  "test_secret_key",
				"traefik_middleware": true, // Legacy field
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jsonPayload, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatalf("Failed to marshal payload: %v", err)
			}
			
			var resp *http.Response
			switch tc.method {
			case "POST":
				resp, err = s.client.Post(s.baseURL+tc.endpoint, "application/json", bytes.NewBuffer(jsonPayload))
			case "PUT":
				req, _ := http.NewRequest("PUT", s.baseURL+tc.endpoint, bytes.NewBuffer(jsonPayload))
				req.Header.Set("Content-Type", "application/json")
				resp, err = s.client.Do(req)
			}
			
			if err != nil {
				t.Fatalf("Failed to make request to %s: %v", tc.endpoint, err)
			}
			defer resp.Body.Close()
			
			// Should accept legacy request format (200 or 201)
			if resp.StatusCode != 200 && resp.StatusCode != 201 {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("Legacy request format rejected for %s: status %d, body: %s", tc.endpoint, resp.StatusCode, string(body))
			}
		})
	}
}

// testLegacyResponseFormats tests that responses maintain legacy format compatibility
func (s *APICompatibilityTestSuite) testLegacyResponseFormats(t *testing.T) {
	testCases := []struct {
		name               string
		endpoint           string
		requiredStructure  map[string]string // field -> expected type
	}{
		{
			name:     "LegacyTraefikIntegration",
			endpoint: "/api/traefik/integration",
			requiredStructure: map[string]string{
				"traefik_enabled":           "bool",
				"traefik_container_name":    "string",
				"traefik_bouncer_configured": "bool",
				"traefik_dynamic_config":    "string",
				"traefik_static_config":     "string",
			},
		},
		{
			name:     "LegacyWhitelistResponse",
			endpoint: "/api/traefik/whitelist",
			requiredStructure: map[string]string{
				"ips":              "array",
				"traefik_enabled":  "bool",
				"crowdsec_enabled": "bool",
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.client.Get(s.baseURL + tc.endpoint)
			if err != nil {
				t.Fatalf("Failed to call endpoint %s: %v", tc.endpoint, err)
			}
			defer resp.Body.Close()
			
			if resp.StatusCode != 200 {
				t.Fatalf("Endpoint %s returned status %d", tc.endpoint, resp.StatusCode)
			}
			
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response body: %v", err)
			}
			
			var response map[string]interface{}
			if err := json.Unmarshal(body, &response); err != nil {
				t.Fatalf("Failed to parse JSON response: %v", err)
			}
			
			// Verify required structure
			for field, expectedType := range tc.requiredStructure {
				value, exists := response[field]
				if !exists {
					t.Errorf("Required field %s not found in response", field)
					continue
				}
				
				if !s.verifyFieldType(value, expectedType) {
					t.Errorf("Field %s has incorrect type: expected %s, got %T", field, expectedType, value)
				}
			}
		})
	}
}

// verifyFieldType checks if a field value matches the expected type
func (s *APICompatibilityTestSuite) verifyFieldType(value interface{}, expectedType string) bool {
	switch expectedType {
	case "string":
		_, ok := value.(string)
		return ok
	case "bool":
		_, ok := value.(bool)
		return ok
	case "number":
		switch value.(type) {
		case float64, int, int64:
			return true
		default:
			return false
		}
	case "array":
		_, ok := value.([]interface{})
		return ok
	case "object":
		_, ok := value.(map[string]interface{})
		return ok
	default:
		return false
	}
}

// TestAPIVersioning tests API versioning compatibility
func TestAPIVersioning(t *testing.T) {
	suite := NewAPICompatibilityTestSuite("http://localhost:8080")
	
	// Test that v1 API endpoints work
	v1Endpoints := []string{
		"/api/v1/health",
		"/api/v1/proxy/current",
		"/api/v1/whitelist",
		"/api/v1/captcha/status",
	}
	
	for _, endpoint := range v1Endpoints {
		t.Run(fmt.Sprintf("V1_%s", strings.ReplaceAll(endpoint, "/", "_")), func(t *testing.T) {
			resp, err := suite.client.Get(suite.baseURL + endpoint)
			if err != nil {
				t.Errorf("Failed to call v1 endpoint %s: %v", endpoint, err)
				return
			}
			defer resp.Body.Close()
			
			// v1 endpoints should work (200) or redirect to current version (301/302)
			if resp.StatusCode != 200 && resp.StatusCode != 301 && resp.StatusCode != 302 {
				t.Errorf("v1 endpoint %s returned unexpected status %d", endpoint, resp.StatusCode)
			}
		})
	}
	
	// Test that unversioned endpoints default to current version
	unversionedEndpoints := []string{
		"/api/health",
		"/api/proxy/current",
		"/api/whitelist",
	}
	
	for _, endpoint := range unversionedEndpoints {
		t.Run(fmt.Sprintf("Unversioned_%s", strings.ReplaceAll(endpoint, "/", "_")), func(t *testing.T) {
			resp, err := suite.client.Get(suite.baseURL + endpoint)
			if err != nil {
				t.Errorf("Failed to call unversioned endpoint %s: %v", endpoint, err)
				return
			}
			defer resp.Body.Close()
			
			if resp.StatusCode != 200 {
				t.Errorf("Unversioned endpoint %s returned status %d", endpoint, resp.StatusCode)
			}
		})
	}
}

// TestContentTypeCompatibility tests content type handling
func TestContentTypeCompatibility(t *testing.T) {
	suite := NewAPICompatibilityTestSuite("http://localhost:8080")
	
	// Test that both application/json and application/x-www-form-urlencoded are accepted
	payload := map[string]interface{}{
		"ip":             "192.168.1.101",
		"add_to_crowdsec": true,
		"add_to_traefik":  true,
	}
	
	t.Run("JSONContentType", func(t *testing.T) {
		jsonPayload, _ := json.Marshal(payload)
		resp, err := suite.client.Post(suite.baseURL+"/api/whitelist", "application/json", bytes.NewBuffer(jsonPayload))
		if err != nil {
			t.Errorf("Failed to post JSON: %v", err)
			return
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != 200 && resp.StatusCode != 201 {
			t.Errorf("JSON content type not accepted: status %d", resp.StatusCode)
		}
	})
	
	t.Run("FormContentType", func(t *testing.T) {
		formData := "ip=192.168.1.102&add_to_crowdsec=true&add_to_traefik=true"
		resp, err := suite.client.Post(suite.baseURL+"/api/whitelist", "application/x-www-form-urlencoded", strings.NewReader(formData))
		if err != nil {
			t.Errorf("Failed to post form data: %v", err)
			return
		}
		defer resp.Body.Close()
		
		// Should accept form data or return appropriate error
		if resp.StatusCode != 200 && resp.StatusCode != 201 && resp.StatusCode != 415 {
			t.Errorf("Unexpected response to form content type: status %d", resp.StatusCode)
		}
	})
}

// TestErrorResponseCompatibility tests that error responses maintain expected format
func TestErrorResponseCompatibility(t *testing.T) {
	suite := NewAPICompatibilityTestSuite("http://localhost:8080")
	
	// Test error response format for invalid requests
	testCases := []struct {
		name     string
		endpoint string
		method   string
		payload  string
		expected int
	}{
		{
			name:     "InvalidJSON",
			endpoint: "/api/whitelist",
			method:   "POST",
			payload:  `{"invalid": json}`,
			expected: 400,
		},
		{
			name:     "MissingRequiredField",
			endpoint: "/api/whitelist",
			method:   "POST",
			payload:  `{"add_to_crowdsec": true}`,
			expected: 400,
		},
		{
			name:     "InvalidIP",
			endpoint: "/api/whitelist",
			method:   "POST",
			payload:  `{"ip": "invalid.ip", "add_to_crowdsec": true}`,
			expected: 400,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := suite.client.Post(suite.baseURL+tc.endpoint, "application/json", strings.NewReader(tc.payload))
			if err != nil {
				t.Errorf("Failed to make request: %v", err)
				return
			}
			defer resp.Body.Close()
			
			if resp.StatusCode != tc.expected {
				t.Errorf("Expected status %d, got %d", tc.expected, resp.StatusCode)
			}
			
			// Verify error response format
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("Failed to read error response: %v", err)
				return
			}
			
			var errorResponse map[string]interface{}
			if err := json.Unmarshal(body, &errorResponse); err != nil {
				t.Errorf("Error response is not valid JSON: %v", err)
				return
			}
			
			// Should have error field
			if _, exists := errorResponse["error"]; !exists {
				t.Error("Error response missing 'error' field")
			}
		})
	}
}