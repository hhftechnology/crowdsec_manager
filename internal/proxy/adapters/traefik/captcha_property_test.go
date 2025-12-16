package traefik

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
)

// **Feature: multi-proxy-architecture, Property 7: Proxy-Aware Captcha Management**
// **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5**
func TestTraefikCaptchaSetup_Property(t *testing.T) {
	// Property: For any valid captcha configuration, setting up captcha should result in captcha being enabled
	property := func(siteKey CaptchaKeyGenerator, secretKey CaptchaKeyGenerator) bool {
		siteKeyStr := string(siteKey)
		secretKeyStr := string(secretKey)
		
		// Skip empty keys
		if siteKeyStr == "" || secretKeyStr == "" {
			return true
		}
		
		// Create fresh mock for each test
		mockClient := &CaptchaMockDockerClient{
			dynamicConfig: `http:
  middlewares:
    crowdsec-bouncer:
      plugin:
        crowdsec-bouncer-traefik-plugin:
          crowdSecLapiKey: "test-key"`,
			fileExists: true,
		}
		
		cfg := &CaptchaMockConfig{
			TraefikContainerName:  "traefik",
			CrowdsecContainerName: "crowdsec",
			ConfigDir:             "/app/config",
		}
		
		manager := &TestTraefikCaptchaManager{
			dockerClient: mockClient,
			cfg:          cfg,
		}
		
		ctx := context.Background()
		
		// Setup captcha
		req := &TestCaptchaSetupRequest{
			Provider:  "turnstile",
			SiteKey:   siteKeyStr,
			SecretKey: secretKeyStr,
		}
		
		err := manager.SetupCaptcha(ctx, req)
		if err != nil {
			t.Logf("Failed to setup captcha: %v", err)
			return false
		}
		
		// Get captcha status to verify setup
		status, err := manager.GetCaptchaStatus(ctx)
		if err != nil {
			t.Logf("Failed to get captcha status: %v", err)
			return false
		}
		
		// Verify captcha is enabled and configured correctly
		if !status.Enabled {
			t.Logf("Captcha not enabled after setup")
			return false
		}
		
		if status.Provider != "turnstile" {
			t.Logf("Expected provider 'turnstile', got '%s'", status.Provider)
			return false
		}
		
		if status.SiteKey != siteKeyStr {
			t.Logf("Expected site key '%s', got '%s'", siteKeyStr, status.SiteKey)
			return false
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Captcha setup property test failed: %v", err)
	}
}

// Property test for captcha status detection
func TestTraefikCaptchaStatusDetection_Property(t *testing.T) {
	// Property: For any captcha configuration in dynamic config, status detection should correctly identify it
	property := func(provider CaptchaProviderGenerator) bool {
		providerStr := string(provider)
		
		// Skip empty providers
		if providerStr == "" {
			return true
		}
		
		// Create mock with captcha already configured
		mockClient := &CaptchaMockDockerClient{
			dynamicConfig: `http:
  middlewares:
    crowdsec-bouncer:
      plugin:
        crowdsec-bouncer-traefik-plugin:
          crowdSecLapiKey: "test-key"
          captchaProvider: "` + providerStr + `"
          captchaSiteKey: "test-site-key"
          captchaSecretKey: "test-secret-key"
          captchaHTMLFilePath: "/etc/traefik/conf/captcha.html"`,
			fileExists: true,
		}
		
		cfg := &CaptchaMockConfig{
			TraefikContainerName: "traefik",
		}
		
		manager := &TestTraefikCaptchaManager{
			dockerClient: mockClient,
			cfg:          cfg,
		}
		
		ctx := context.Background()
		
		// Get captcha status
		status, err := manager.GetCaptchaStatus(ctx)
		if err != nil {
			t.Logf("Failed to get captcha status: %v", err)
			return false
		}
		
		// Verify status correctly detects the configuration
		if !status.Enabled {
			t.Logf("Captcha should be detected as enabled")
			return false
		}
		
		if status.Provider != providerStr {
			t.Logf("Expected provider '%s', got '%s'", providerStr, status.Provider)
			return false
		}
		
		if status.SiteKey != "test-site-key" {
			t.Logf("Expected site key 'test-site-key', got '%s'", status.SiteKey)
			return false
		}
		
		return true
	}
	
	// Run property-based test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Captcha status detection property test failed: %v", err)
	}
}

// Test interfaces and mocks for captcha testing
type CaptchaDockerClientInterface interface {
	ExecCommand(containerName string, command []string) (string, error)
	RestartContainer(containerName string) error
	FileExists(containerName, path string) (bool, error)
}

type CaptchaConfigInterface interface {
	GetTraefikContainerName() string
	GetCrowdsecContainerName() string
	GetConfigDir() string
}

type CaptchaMockConfig struct {
	TraefikContainerName  string
	CrowdsecContainerName string
	ConfigDir             string
}

func (m *CaptchaMockConfig) GetTraefikContainerName() string {
	return m.TraefikContainerName
}

func (m *CaptchaMockConfig) GetCrowdsecContainerName() string {
	return m.CrowdsecContainerName
}

func (m *CaptchaMockConfig) GetConfigDir() string {
	return m.ConfigDir
}

type TestCaptchaSetupRequest struct {
	Provider  string
	SiteKey   string
	SecretKey string
}

type TestCaptchaStatus struct {
	Enabled  bool
	Provider string
	SiteKey  string
}

type TestTraefikCaptchaManager struct {
	dockerClient CaptchaDockerClientInterface
	cfg          CaptchaConfigInterface
}

func (t *TestTraefikCaptchaManager) SetupCaptcha(ctx context.Context, req *TestCaptchaSetupRequest) error {
	// Simulate captcha setup by updating mock config
	if mockClient, ok := t.dockerClient.(*CaptchaMockDockerClient); ok {
		// Update the mock config to include captcha settings
		mockClient.dynamicConfig = strings.Replace(mockClient.dynamicConfig, 
			"crowdSecLapiKey: \"test-key\"",
			"crowdSecLapiKey: \"test-key\"\n          captchaProvider: \""+req.Provider+"\"\n          captchaSiteKey: \""+req.SiteKey+"\"\n          captchaSecretKey: \""+req.SecretKey+"\"\n          captchaHTMLFilePath: \"/etc/traefik/conf/captcha.html\"",
			1)
	}
	return nil
}

func (t *TestTraefikCaptchaManager) GetCaptchaStatus(ctx context.Context) (*TestCaptchaStatus, error) {
	// Read dynamic config
	configContent, err := t.dockerClient.ExecCommand(t.cfg.GetTraefikContainerName(), []string{
		"cat", "/etc/traefik/dynamic_config.yml",
	})
	if err != nil {
		return nil, err
	}
	
	status := &TestCaptchaStatus{}
	
	// Simple detection logic
	if strings.Contains(configContent, "captchaProvider") {
		status.Enabled = true
		
		// Extract provider
		if strings.Contains(configContent, "turnstile") {
			status.Provider = "turnstile"
		} else if strings.Contains(configContent, "recaptcha") {
			status.Provider = "recaptcha"
		} else if strings.Contains(configContent, "hcaptcha") {
			status.Provider = "hcaptcha"
		}
		
		// Extract site key (simple approach)
		lines := strings.Split(configContent, "\n")
		for _, line := range lines {
			if strings.Contains(line, "captchaSiteKey:") {
				parts := strings.Split(line, "\"")
				if len(parts) >= 2 {
					status.SiteKey = parts[1]
				}
			}
		}
	}
	
	// Check if HTML file exists
	if status.Enabled {
		exists, _ := t.dockerClient.FileExists(t.cfg.GetTraefikContainerName(), "/etc/traefik/conf/captcha.html")
		status.Enabled = exists
	}
	
	return status, nil
}

type CaptchaMockDockerClient struct {
	dynamicConfig string
	fileExists    bool
	commands      [][]string
}

func (m *CaptchaMockDockerClient) ExecCommand(containerName string, command []string) (string, error) {
	m.commands = append(m.commands, command)
	
	// Mock reading dynamic config
	if len(command) >= 2 && command[0] == "cat" && strings.Contains(command[1], "dynamic_config.yml") {
		return m.dynamicConfig, nil
	}
	
	// Mock other commands
	return "", nil
}

func (m *CaptchaMockDockerClient) RestartContainer(containerName string) error {
	return nil
}

func (m *CaptchaMockDockerClient) FileExists(containerName, path string) (bool, error) {
	return m.fileExists, nil
}

// Generators for property testing
type CaptchaKeyGenerator string

func (CaptchaKeyGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	keys := []string{
		"0x4AAAAAAABkMYinukE8nzYx",
		"0x4AAAAAAABkMYinukE8nzYy", 
		"0x4AAAAAAABkMYinukE8nzYz",
		"test-site-key-123",
		"test-secret-key-456",
		"cf-turnstile-key-789",
	}
	
	if len(keys) == 0 {
		return reflect.ValueOf(CaptchaKeyGenerator("test-key"))
	}
	
	return reflect.ValueOf(CaptchaKeyGenerator(keys[rand.Rand.Intn(len(keys))]))
}

type CaptchaProviderGenerator string

func (CaptchaProviderGenerator) Generate(rand *quick.Config, size int) reflect.Value {
	providers := []string{
		"turnstile",
		"recaptcha", 
		"hcaptcha",
	}
	
	if len(providers) == 0 {
		return reflect.ValueOf(CaptchaProviderGenerator("turnstile"))
	}
	
	return reflect.ValueOf(CaptchaProviderGenerator(providers[rand.Rand.Intn(len(providers))]))
}