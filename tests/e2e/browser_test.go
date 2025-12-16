package e2e

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
)

// BrowserTestSuite contains browser automation tests
type BrowserTestSuite struct {
	env *TestEnvironment
	ctx context.Context
}

// NewBrowserTestSuite creates a new browser test suite
func NewBrowserTestSuite(env *TestEnvironment) *BrowserTestSuite {
	// Create Chrome context
	ctx, _ := chromedp.NewContext(context.Background())
	
	return &BrowserTestSuite{
		env: env,
		ctx: ctx,
	}
}

// TestUIWorkflows tests complete UI workflows for different proxy types
func TestUIWorkflows(t *testing.T) {
	proxyTypes := []string{"traefik", "nginx", "caddy", "haproxy", "zoraxy", "standalone"}
	
	for _, proxyType := range proxyTypes {
		t.Run(fmt.Sprintf("UI_Workflow_%s", proxyType), func(t *testing.T) {
			env := SetupTestEnvironment(t, proxyType, "single")
			defer env.Cleanup()
			
			suite := NewBrowserTestSuite(env)
			suite.testCompleteWorkflow(t)
		})
	}
}

// testCompleteWorkflow tests a complete user workflow
func (s *BrowserTestSuite) testCompleteWorkflow(t *testing.T) {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Minute)
	defer cancel()
	
	// Start services
	if err := s.env.StartServices(ctx); err != nil {
		t.Fatalf("Failed to start services: %v", err)
	}
	defer s.env.StopServices(ctx)
	
	// Wait for services to be ready
	if err := s.env.WaitForServices(ctx, 2*time.Minute); err != nil {
		t.Fatalf("Services not ready: %v", err)
	}
	
	// Wait for web interface to be available
	if err := s.waitForWebInterface(ctx); err != nil {
		t.Fatalf("Web interface not available: %v", err)
	}
	
	// Test navigation and proxy detection
	s.testNavigationAndProxyDetection(t, ctx)
	
	// Test proxy-specific features
	s.testProxySpecificFeatures(t, ctx)
	
	// Test health monitoring
	s.testHealthMonitoring(t, ctx)
	
	// Test configuration management
	s.testConfigurationManagement(t, ctx)
}

// waitForWebInterface waits for the web interface to be available
func (s *BrowserTestSuite) waitForWebInterface(ctx context.Context) error {
	url := s.env.GetServiceURL("crowdsec-manager")
	
	for i := 0; i < 30; i++ {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(2 * time.Second)
	}
	
	return fmt.Errorf("web interface not available at %s", url)
}

// testNavigationAndProxyDetection tests navigation and proxy type detection
func (s *BrowserTestSuite) testNavigationAndProxyDetection(t *testing.T, ctx context.Context) {
	url := s.env.GetServiceURL("crowdsec-manager")
	
	var title string
	var proxyStatus string
	
	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.Title(&title),
		chromedp.Text("[data-testid='proxy-status']", &proxyStatus, chromedp.ByQuery),
	)
	
	if err != nil {
		t.Fatalf("Failed to navigate and detect proxy: %v", err)
	}
	
	// Verify page loaded
	if title == "" {
		t.Error("Page title is empty")
	}
	
	// Verify proxy type is detected
	expectedProxy := s.env.ProxyType
	if expectedProxy == "nginx" {
		expectedProxy = "nginx" // NPM shows as nginx
	}
	
	if proxyStatus == "" {
		t.Error("Proxy status not found")
	}
	
	t.Logf("Page title: %s, Proxy status: %s", title, proxyStatus)
}

// testProxySpecificFeatures tests features specific to the proxy type
func (s *BrowserTestSuite) testProxySpecificFeatures(t *testing.T, ctx context.Context) {
	url := s.env.GetServiceURL("crowdsec-manager")
	
	// Navigate to features page
	err := chromedp.Run(ctx,
		chromedp.Navigate(url+"/features"),
		chromedp.WaitVisible("body", chromedp.ByQuery),
	)
	
	if err != nil {
		t.Fatalf("Failed to navigate to features page: %v", err)
	}
	
	// Test feature availability based on proxy type
	s.testFeatureAvailability(t, ctx)
}

// testFeatureAvailability tests that features are shown/hidden correctly
func (s *BrowserTestSuite) testFeatureAvailability(t *testing.T, ctx context.Context) {
	proxyType := s.env.ProxyType
	
	// Define expected features for each proxy type
	expectedFeatures := map[string][]string{
		"traefik":    {"whitelist", "captcha", "logs", "bouncer", "health"},
		"nginx":      {"logs", "bouncer", "health"},
		"caddy":      {"bouncer", "health"},
		"haproxy":    {"bouncer", "health"},
		"zoraxy":     {"health"},
		"standalone": {"health"},
	}
	
	features := expectedFeatures[proxyType]
	
	for _, feature := range features {
		var isVisible bool
		selector := fmt.Sprintf("[data-testid='feature-%s']", feature)
		
		err := chromedp.Run(ctx,
			chromedp.Evaluate(fmt.Sprintf(`document.querySelector('%s') !== null`, selector), &isVisible),
		)
		
		if err != nil {
			t.Errorf("Failed to check feature %s visibility: %v", feature, err)
			continue
		}
		
		if !isVisible {
			t.Errorf("Feature %s should be visible for proxy type %s", feature, proxyType)
		}
	}
	
	// Test that unsupported features are hidden
	allFeatures := []string{"whitelist", "captcha", "logs", "bouncer", "health"}
	for _, feature := range allFeatures {
		found := false
		for _, supported := range features {
			if feature == supported {
				found = true
				break
			}
		}
		
		if !found {
			var isVisible bool
			selector := fmt.Sprintf("[data-testid='feature-%s']", feature)
			
			err := chromedp.Run(ctx,
				chromedp.Evaluate(fmt.Sprintf(`document.querySelector('%s') !== null`, selector), &isVisible),
			)
			
			if err == nil && isVisible {
				t.Errorf("Feature %s should be hidden for proxy type %s", feature, proxyType)
			}
		}
	}
}

// testHealthMonitoring tests the health monitoring interface
func (s *BrowserTestSuite) testHealthMonitoring(t *testing.T, ctx context.Context) {
	url := s.env.GetServiceURL("crowdsec-manager")
	
	var healthStatus string
	
	err := chromedp.Run(ctx,
		chromedp.Navigate(url+"/health"),
		chromedp.WaitVisible("[data-testid='health-dashboard']", chromedp.ByQuery),
		chromedp.Text("[data-testid='overall-health']", &healthStatus, chromedp.ByQuery),
	)
	
	if err != nil {
		t.Fatalf("Failed to test health monitoring: %v", err)
	}
	
	if healthStatus == "" {
		t.Error("Health status not found")
	}
	
	// Test proxy-specific health indicators
	if s.env.ProxyType != "standalone" {
		var proxyHealth string
		
		err = chromedp.Run(ctx,
			chromedp.Text(fmt.Sprintf("[data-testid='%s-health']", s.env.ProxyType), &proxyHealth, chromedp.ByQuery),
		)
		
		if err != nil {
			t.Errorf("Failed to get proxy health for %s: %v", s.env.ProxyType, err)
		}
	}
}

// testConfigurationManagement tests configuration management interface
func (s *BrowserTestSuite) testConfigurationManagement(t *testing.T, ctx context.Context) {
	url := s.env.GetServiceURL("crowdsec-manager")
	
	err := chromedp.Run(ctx,
		chromedp.Navigate(url+"/configuration"),
		chromedp.WaitVisible("[data-testid='config-panel']", chromedp.ByQuery),
	)
	
	if err != nil {
		t.Fatalf("Failed to navigate to configuration: %v", err)
	}
	
	// Test that proxy type is displayed correctly
	var displayedProxyType string
	
	err = chromedp.Run(ctx,
		chromedp.Text("[data-testid='current-proxy-type']", &displayedProxyType, chromedp.ByQuery),
	)
	
	if err != nil {
		t.Errorf("Failed to get displayed proxy type: %v", err)
	} else if displayedProxyType != s.env.ProxyType {
		t.Errorf("Expected proxy type %s, got %s", s.env.ProxyType, displayedProxyType)
	}
}

// TestResponsiveDesign tests responsive design across different screen sizes
func TestResponsiveDesign(t *testing.T) {
	env := SetupTestEnvironment(t, "traefik", "single")
	defer env.Cleanup()
	
	// Start services
	ctx := context.Background()
	if err := env.StartServices(ctx); err != nil {
		t.Fatalf("Failed to start services: %v", err)
	}
	defer env.StopServices(ctx)
	
	// Wait for services
	if err := env.WaitForServices(ctx, 2*time.Minute); err != nil {
		t.Fatalf("Services not ready: %v", err)
	}
	
	// Test different screen sizes
	screenSizes := []struct {
		name   string
		width  int64
		height int64
	}{
		{"Desktop", 1920, 1080},
		{"Tablet", 768, 1024},
		{"Mobile", 375, 667},
	}
	
	for _, size := range screenSizes {
		t.Run(size.name, func(t *testing.T) {
			testResponsiveLayout(t, env, size.width, size.height)
		})
	}
}

// testResponsiveLayout tests layout at specific screen size
func testResponsiveLayout(t *testing.T, env *TestEnvironment, width, height int64) {
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()
	
	url := env.GetServiceURL("crowdsec-manager")
	
	var sidebarVisible bool
	var mobileMenuVisible bool
	
	err := chromedp.Run(ctx,
		chromedp.EmulateViewport(width, height),
		chromedp.Navigate(url),
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.Evaluate(`document.querySelector('[data-testid="sidebar"]').offsetWidth > 0`, &sidebarVisible),
		chromedp.Evaluate(`document.querySelector('[data-testid="mobile-menu"]') !== null`, &mobileMenuVisible),
	)
	
	if err != nil {
		t.Fatalf("Failed to test responsive layout: %v", err)
	}
	
	// Verify responsive behavior
	if width < 768 {
		// Mobile: sidebar should be hidden, mobile menu should be available
		if sidebarVisible {
			t.Error("Sidebar should be hidden on mobile")
		}
		if !mobileMenuVisible {
			t.Error("Mobile menu should be available on mobile")
		}
	} else {
		// Desktop/Tablet: sidebar should be visible
		if !sidebarVisible {
			t.Error("Sidebar should be visible on desktop/tablet")
		}
	}
}

// TestAccessibility tests accessibility features
func TestAccessibility(t *testing.T) {
	env := SetupTestEnvironment(t, "traefik", "single")
	defer env.Cleanup()
	
	ctx := context.Background()
	if err := env.StartServices(ctx); err != nil {
		t.Fatalf("Failed to start services: %v", err)
	}
	defer env.StopServices(ctx)
	
	if err := env.WaitForServices(ctx, 2*time.Minute); err != nil {
		t.Fatalf("Services not ready: %v", err)
	}
	
	chromeCtx, cancel := chromedp.NewContext(context.Background())
	defer cancel()
	
	url := env.GetServiceURL("crowdsec-manager")
	
	// Test keyboard navigation
	err := chromedp.Run(chromeCtx,
		chromedp.Navigate(url),
		chromedp.WaitVisible("body", chromedp.ByQuery),
		// Test tab navigation
		chromedp.KeyEvent("Tab"),
		chromedp.KeyEvent("Tab"),
		chromedp.KeyEvent("Enter"),
	)
	
	if err != nil {
		t.Fatalf("Failed to test keyboard navigation: %v", err)
	}
	
	// Test ARIA labels
	var ariaLabels []string
	
	err = chromedp.Run(chromeCtx,
		chromedp.Evaluate(`Array.from(document.querySelectorAll('[aria-label]')).map(el => el.getAttribute('aria-label'))`, &ariaLabels),
	)
	
	if err != nil {
		t.Fatalf("Failed to check ARIA labels: %v", err)
	}
	
	if len(ariaLabels) == 0 {
		t.Error("No ARIA labels found - accessibility may be compromised")
	}
	
	t.Logf("Found %d ARIA labels", len(ariaLabels))
}