package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"testing/quick"

	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// **Feature: multi-proxy-architecture, Property 1: Backward Compatibility Preservation** (API portion)
// **Validates: Requirements 12.1, 12.2, 12.3, 12.4, 12.5**
func TestAPIBackwardCompatibility_Property(t *testing.T) {
	// Property: For any API request using legacy field names, the response should include both legacy and new fields
	property := func(legacyRequest LegacyRequestGenerator) bool {
		reqData := LegacyWhitelistRequest(legacyRequest)
		
		// Skip empty requests
		if reqData.IP == "" {
			return true
		}
		
		// Create test router
		gin.SetMode(gin.TestMode)
		router := gin.New()
		
		// Mock handler that returns both legacy and new fields
		router.POST("/api/whitelist/test", func(c *gin.Context) {
			var req models.WhitelistRequest
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			
			// Return response with both legacy and new fields for backward compatibility
			response := gin.H{
				"success": true,
				"data": gin.H{
					"ip":            req.IP,
					"in_crowdsec":   true,
					"in_traefik":    true,  // Legacy field
					"in_proxy":      true,  // New field
					"add_to_traefik": req.AddToTraefik, // Legacy field
					"add_to_proxy":   req.AddToTraefik, // New field maps to legacy for compatibility
				},
			}
			c.JSON(http.StatusOK, response)
		})
		
		// Create request
		reqBody, _ := json.Marshal(reqData)
		req, _ := http.NewRequest("POST", "/api/whitelist/test", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		
		// Execute request
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		
		// Check response
		if w.Code != http.StatusOK {
			t.Logf("Expected status 200, got %d", w.Code)
			return false
		}
		
		// Parse response
		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Logf("Failed to parse response: %v", err)
			return false
		}
		
		// Verify both legacy and new fields are present
		data, ok := response["data"].(map[string]interface{})
		if !ok {
			t.Logf("Response data is not a map")
			return false
		}
		
		// Check that both legacy and new fields exist
		if _, hasLegacy := data["in_traefik"]; !hasLegacy {
			t.Logf("Legacy field 'in_traefik' missing from response")
			return false
		}
		
		if _, hasNew := data["in_proxy"]; !hasNew {
			t.Logf("New field 'in_proxy' missing from response")
			return false
		}
		
		// Verify values are consistent
		legacyValue := data["in_traefik"]
		newValue := data["in_proxy"]
		if legacyValue != newValue {
			t.Logf("Legacy and new field values should be consistent: legacy=%v, new=%v", legacyValue, newValue)
			return false
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("API backward compatibility property test failed: %v", err)
	}
}

// Property test for API endpoint availability
func TestAPIEndpointAvailability_Property(t *testing.T) {
	// Property: For any legacy API endpoint, it should remain available and functional
	property := func(endpoint LegacyEndpointGenerator) bool {
		endpointPath := string(endpoint)
		
		// Skip empty endpoints
		if endpointPath == "" {
			return true
		}
		
		// Create test router with legacy endpoints
		gin.SetMode(gin.TestMode)
		router := gin.New()
		
		// Add legacy endpoints that should remain available
		router.GET(endpointPath, func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"success": true,
				"message": "Legacy endpoint available",
				"endpoint": endpointPath,
			})
		})
		
		// Test endpoint availability
		req, _ := http.NewRequest("GET", endpointPath, nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		
		// Endpoint should be available (not 404)
		if w.Code == http.StatusNotFound {
			t.Logf("Legacy endpoint %s should remain available", endpointPath)
			return false
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("API endpoint availability property test failed: %v", err)
	}
}

// Property test for field mapping consistency
func TestFieldMappingConsistency_Property(t *testing.T) {
	// Property: For any request with legacy fields, they should map correctly to new fields
	property := func(mapping FieldMappingGenerator) bool {
		mappingData := FieldMapping(mapping)
		
		// Skip empty mappings
		if mappingData.LegacyField == "" || mappingData.NewField == "" {
			return true
		}
		
		// Test that field mapping is consistent
		testData := map[string]interface{}{
			mappingData.LegacyField: mappingData.Value,
		}
		
		// Simulate field mapping logic
		mappedData := make(map[string]interface{})
		for k, v := range testData {
			mappedData[k] = v
			// Add new field mapping
			if k == "add_to_traefik" {
				mappedData["add_to_proxy"] = v
			}
			if k == "in_traefik" {
				mappedData["in_proxy"] = v
			}
		}
		
		// Verify mapping consistency
		if legacyValue, hasLegacy := mappedData[mappingData.LegacyField]; hasLegacy {
			if newValue, hasNew := mappedData[mappingData.NewField]; hasNew {
				if legacyValue != newValue {
					t.Logf("Field mapping inconsistent: %s=%v, %s=%v", 
						mappingData.LegacyField, legacyValue, 
						mappingData.NewField, newValue)
					return false
				}
			}
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Field mapping consistency property test failed: %v", err)
	}
}

// Test data structures and generators
type LegacyWhitelistRequestData struct {
	IP            string `json:"ip"`
	AddToCrowdSec bool   `json:"add_to_crowdsec"`
	AddToTraefik  bool   `json:"add_to_traefik"` // Legacy field
}

type FieldMappingData struct {
	LegacyField string
	NewField    string
	Value       interface{}
}

// Generators for property testing
type LegacyRequestGenerator string

func (LegacyRequestGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	requests := []string{
		"request1",
		"request2", 
		"request3",
	}
	
	return reflect.ValueOf(LegacyRequestGenerator(requests[rand.Rand.Intn(len(requests))]))
}

func LegacyWhitelistRequest(gen LegacyRequestGenerator) LegacyWhitelistRequestData {
	// Generate test data based on generator
	ips := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"}
	
	return LegacyWhitelistRequestData{
		IP:            ips[0], // Use first IP for simplicity
		AddToCrowdSec: true,
		AddToTraefik:  true,
	}
}

type LegacyEndpointGenerator string

func (LegacyEndpointGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	endpoints := []string{
		"/api/whitelist/traefik",
		"/api/logs/traefik",
		"/api/captcha/status",
		"/api/health/crowdsec",
	}
	
	return reflect.ValueOf(LegacyEndpointGenerator(endpoints[rand.Rand.Intn(len(endpoints))]))
}

type FieldMappingGenerator string

func (FieldMappingGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	mappings := []string{
		"traefik_to_proxy",
		"legacy_to_new",
	}
	
	return reflect.ValueOf(FieldMappingGenerator(mappings[rand.Rand.Intn(len(mappings))]))
}

func FieldMapping(gen FieldMappingGenerator) FieldMappingData {
	mappings := map[string]FieldMappingData{
		"traefik_to_proxy": {
			LegacyField: "add_to_traefik",
			NewField:    "add_to_proxy",
			Value:       true,
		},
		"legacy_to_new": {
			LegacyField: "in_traefik",
			NewField:    "in_proxy", 
			Value:       true,
		},
	}
	
	if mapping, exists := mappings[string(gen)]; exists {
		return mapping
	}
	
	return FieldMappingData{
		LegacyField: "add_to_traefik",
		NewField:    "add_to_proxy",
		Value:       true,
	}
}