package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ProxyIntegrationTest tests proxy-specific integration scenarios
type ProxyIntegrationTest struct {
	env    *TestEnvironment
	client *http.Client
}

// NewProxyIntegrationTest creates a new proxy integration test
func NewProxyIntegrationTest(env *TestEnvironment) *ProxyIntegrationTest {
	return &ProxyIntegrationTest{
		env: env,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// TestProxyIntegration tests integration with each proxy type
func TestProxyIntegration(t *testing.T) {
	proxyTypes := []string{"traefik", "nginx", "caddy", "haproxy", "zoraxy", "standalone"}
	
	for _, proxyType := range proxyTypes {
		t.Run(fmt.Sprintf("Proxy_Integration_%s", proxyType), func(t *testing.T) {
			env := SetupTestEnvironment(t, proxyType, "single")
			defer env.Cleanup()
			
			test := NewProxyIntegrationTest(env)
			test.runProxyIntegrationTest(t)
		})
	}
}

// runProxyIntegrationTest runs the complete proxy integration test
func (p *ProxyIntegrationTest) runProxyIntegrationTest(t *testing.T) {
	ctx := context.Background()
	
	// Start services
	if err := p.env.StartServices(ctx); err != nil {
		t.Fatalf("Failed to start services: %v", err)
	}
	defer p.env.StopServices(ctx)
	
	// Wait for services to be ready
	if err := p.env.WaitForServices(ctx, 2*time.Minute); err != nil {
		t.Fatalf("Services not ready: %v", err)
	}
	
	// Test API endpoints
	p.testAPIEndpoints(t)
	
	// Test proxy-specific features
	p.testProxySpecificFeatures(t)
	
	// Test health monitoring
	p.testHealthMonitoring(t)
	
	// Test configuration management
	p.testConfigurationManagement(t)
	
	// Test backward compatibility
	p.testBackwardCompatibility(t)
}

// testAPIEndpoints tests core API endpoints
func (p *ProxyIntegrationTest) testAPIEndpoints(t *testing.T) {
	baseURL := p.env.GetServiceURL("crowdsec-manager")
	
	// Test health endpoint
	resp, err := p.client.Get(baseURL + "/api/health")
	if err != nil {
		t.Fatalf("Failed to call health endpoint: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Health endpoint returned status %d", resp.StatusCode)
	}
	
	// Test proxy info endpoint
	resp, err = p.client.Get(baseURL + "/api/proxy/current")
	if err != nil {
		t.Fatalf("Failed to call proxy info endpoint: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Proxy info endpoint returned status %d", resp.StatusCode)
	}
	
	// Verify proxy type in response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	
	var proxyInfo map[string]interface{}
	if err := json.Unmarshal(body, &proxyInfo); err != nil {
		t.Fatalf("Failed to parse proxy info response: %v", err)
	}
	
	if proxyType, ok := proxyInfo["type"].(string); !ok || proxyType != p.env.ProxyType {
		t.Errorf("Expected proxy type %s, got %v", p.env.ProxyType, proxyInfo["type"])
	}
	
	// Test proxy types endpoint
	resp, err = p.client.Get(baseURL + "/api/proxy/types")
	if err != nil {
		t.Fatalf("Failed to call proxy types endpoint: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Proxy types endpoint returned status %d", resp.StatusCode)
	}
}

// testProxySpecificFeatures tests features specific to each proxy type
func (p *ProxyIntegrationTest) testProxySpecificFeatures(t *testing.T) {
	baseURL := p.env.GetServiceURL("crowdsec-manager")
	
	switch p.env.ProxyType {
	case "traefik":
		p.testTraefikFeatures(t, baseURL)
	case "nginx":
		p.testNginxFeatures(t, baseURL)
	case "caddy":
		p.testCaddyFeatures(t, baseURL)
	case "haproxy":
		p.testHAProxyFeatures(t, baseURL)
	case "zoraxy":
		p.testZoraxyFeatures(t, baseURL)
	case "standalone":
		p.testStandaloneFeatures(t, baseURL)
	}
}

// testTraefikFeatures tests Traefik-specific features
func (p *ProxyIntegrationTest) testTraefikFeatures(t *testing.T, baseURL string) {
	// Test whitelist management
	resp, err := p.client.Get(baseURL + "/api/whitelist")
	if err != nil {
		t.Errorf("Failed to call whitelist endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Whitelist endpoint returned status %d", resp.StatusCode)
		}
	}
	
	// Test captcha configuration
	resp, err = p.client.Get(baseURL + "/api/captcha/status")
	if err != nil {
		t.Errorf("Failed to call captcha status endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Captcha status endpoint returned status %d", resp.StatusCode)
		}
	}
	
	// Test log access
	resp, err = p.client.Get(baseURL + "/api/logs/access?tail=10")
	if err != nil {
		t.Errorf("Failed to call access logs endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		// May return 404 if no logs exist yet, which is acceptable
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			t.Errorf("Access logs endpoint returned unexpected status %d", resp.StatusCode)
		}
	}
}

// testNginxFeatures tests Nginx Proxy Manager-specific features
func (p *ProxyIntegrationTest) testNginxFeatures(t *testing.T, baseURL string) {
	// Test log access (should be available)
	resp, err := p.client.Get(baseURL + "/api/logs/access?tail=10")
	if err != nil {
		t.Errorf("Failed to call access logs endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		// May return 404 if no logs exist yet
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
			t.Errorf("Access logs endpoint returned unexpected status %d", resp.StatusCode)
		}
	}
	
	// Test whitelist (should not be available at proxy level)
	resp, err = p.client.Get(baseURL + "/api/whitelist")
	if err != nil {
		t.Errorf("Failed to call whitelist endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		// Should indicate feature not supported
		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), "not supported") {
				t.Error("Whitelist should indicate not supported for Nginx")
			}
		}
	}
}

// testCaddyFeatures tests Caddy-specific features
func (p *ProxyIntegrationTest) testCaddyFeatures(t *testing.T, baseURL string) {
	// Test bouncer status
	resp, err := p.client.Get(baseURL + "/api/bouncer/status")
	if err != nil {
		t.Errorf("Failed to call bouncer status endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Bouncer status endpoint returned status %d", resp.StatusCode)
		}
	}
	
	// Test that advanced features are not available
	resp, err = p.client.Get(baseURL + "/api/whitelist")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), "not supported") {
				t.Error("Whitelist should indicate not supported for Caddy")
			}
		}
	}
}

// testHAProxyFeatures tests HAProxy-specific features
func (p *ProxyIntegrationTest) testHAProxyFeatures(t *testing.T, baseURL string) {
	// Test bouncer status (SPOA integration)
	resp, err := p.client.Get(baseURL + "/api/bouncer/status")
	if err != nil {
		t.Errorf("Failed to call bouncer status endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Bouncer status endpoint returned status %d", resp.StatusCode)
		}
	}
}

// testZoraxyFeatures tests Zoraxy-specific features (experimental)
func (p *ProxyIntegrationTest) testZoraxyFeatures(t *testing.T, baseURL string) {
	// Test basic health monitoring
	resp, err := p.client.Get(baseURL + "/api/health")
	if err != nil {
		t.Errorf("Failed to call health endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Health endpoint returned status %d", resp.StatusCode)
		}
	}
	
	// Verify experimental status is indicated
	resp, err = p.client.Get(baseURL + "/api/proxy/current")
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "experimental") {
			t.Error("Zoraxy should be marked as experimental")
		}
	}
}

// testStandaloneFeatures tests standalone mode features
func (p *ProxyIntegrationTest) testStandaloneFeatures(t *testing.T, baseURL string) {
	// Test that only CrowdSec features are available
	resp, err := p.client.Get(baseURL + "/api/health")
	if err != nil {
		t.Errorf("Failed to call health endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Health endpoint returned status %d", resp.StatusCode)
		}
	}
	
	// Test that proxy-specific features return appropriate responses
	resp, err = p.client.Get(baseURL + "/api/whitelist")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), "standalone") {
				t.Error("Whitelist should indicate standalone mode")
			}
		}
	}
}

// testHealthMonitoring tests health monitoring functionality
func (p *ProxyIntegrationTest) testHealthMonitoring(t *testing.T) {
	baseURL := p.env.GetServiceURL("crowdsec-manager")
	
	// Test comprehensive health endpoint
	resp, err := p.client.Get(baseURL + "/api/health/comprehensive")
	if err != nil {
		t.Errorf("Failed to call comprehensive health endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Comprehensive health endpoint returned status %d", resp.StatusCode)
		}
		
		// Parse and verify health data
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Failed to read health response: %v", err)
		} else {
			var health map[string]interface{}
			if err := json.Unmarshal(body, &health); err != nil {
				t.Errorf("Failed to parse health response: %v", err)
			} else {
				// Verify required health components
				if _, ok := health["crowdsec"]; !ok {
					t.Error("CrowdSec health not found in response")
				}
				
				if p.env.ProxyType != "standalone" {
					if _, ok := health["proxy"]; !ok {
						t.Error("Proxy health not found in response")
					}
				}
			}
		}
	}
}

// testConfigurationManagement tests configuration management
func (p *ProxyIntegrationTest) testConfigurationManagement(t *testing.T) {
	baseURL := p.env.GetServiceURL("crowdsec-manager")
	
	// Test proxy configuration endpoint
	resp, err := p.client.Get(baseURL + "/api/proxy/configure")
	if err != nil {
		t.Errorf("Failed to call proxy configure endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		// May return method not allowed for GET, which is acceptable
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("Proxy configure endpoint returned unexpected status %d", resp.StatusCode)
		}
	}
	
	// Test features endpoint
	resp, err = p.client.Get(baseURL + "/api/proxy/features")
	if err != nil {
		t.Errorf("Failed to call proxy features endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Proxy features endpoint returned status %d", resp.StatusCode)
		}
		
		// Verify features match proxy type
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Failed to read features response: %v", err)
		} else {
			var features map[string]interface{}
			if err := json.Unmarshal(body, &features); err != nil {
				t.Errorf("Failed to parse features response: %v", err)
			} else {
				p.verifyExpectedFeatures(t, features)
			}
		}
	}
}

// verifyExpectedFeatures verifies that the returned features match expectations
func (p *ProxyIntegrationTest) verifyExpectedFeatures(t *testing.T, features map[string]interface{}) {
	expectedFeatures := map[string][]string{
		"traefik":    {"whitelist", "captcha", "logs", "bouncer", "health"},
		"nginx":      {"logs", "bouncer", "health"},
		"caddy":      {"bouncer", "health"},
		"haproxy":    {"bouncer", "health"},
		"zoraxy":     {"health"},
		"standalone": {"health"},
	}
	
	expected := expectedFeatures[p.env.ProxyType]
	
	for _, feature := range expected {
		if _, ok := features[feature]; !ok {
			t.Errorf("Expected feature %s not found for proxy type %s", feature, p.env.ProxyType)
		}
	}
	
	// Check that unsupported features are not present or marked as unsupported
	allFeatures := []string{"whitelist", "captcha", "logs", "bouncer", "health"}
	for _, feature := range allFeatures {
		supported := false
		for _, exp := range expected {
			if feature == exp {
				supported = true
				break
			}
		}
		
		if !supported {
			if featureData, ok := features[feature]; ok {
				if featureMap, ok := featureData.(map[string]interface{}); ok {
					if supported, ok := featureMap["supported"].(bool); ok && supported {
						t.Errorf("Feature %s should not be supported for proxy type %s", feature, p.env.ProxyType)
					}
				}
			}
		}
	}
}

// testBackwardCompatibility tests backward compatibility with legacy API
func (p *ProxyIntegrationTest) testBackwardCompatibility(t *testing.T) {
	baseURL := p.env.GetServiceURL("crowdsec-manager")
	
	// Test legacy Traefik endpoints still work
	if p.env.ProxyType == "traefik" {
		// Test legacy whitelist endpoint
		resp, err := p.client.Get(baseURL + "/api/traefik/whitelist")
		if err != nil {
			t.Errorf("Failed to call legacy whitelist endpoint: %v", err)
		} else {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("Legacy whitelist endpoint returned status %d", resp.StatusCode)
			}
		}
	}
	
	// Test that responses include both legacy and new field formats
	resp, err := p.client.Get(baseURL + "/api/proxy/current")
	if err != nil {
		t.Errorf("Failed to call proxy current endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("Failed to read response: %v", err)
		} else {
			var data map[string]interface{}
			if err := json.Unmarshal(body, &data); err != nil {
				t.Errorf("Failed to parse response: %v", err)
			} else {
				// Should have both legacy and new fields
				if p.env.ProxyType == "traefik" {
					if _, ok := data["traefik_enabled"]; !ok {
						t.Error("Legacy traefik_enabled field not found")
					}
				}
				if _, ok := data["proxy_enabled"]; !ok {
					t.Error("New proxy_enabled field not found")
				}
			}
		}
	}
}