package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestEnvironment represents an end-to-end test environment
type TestEnvironment struct {
	WorkDir     string
	ProxyType   string
	ComposeMode string
	Services    []string
	Cleanup     func() error
}

// SetupTestEnvironment creates a test environment for end-to-end testing
func SetupTestEnvironment(t *testing.T, proxyType, composeMode string) *TestEnvironment {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", fmt.Sprintf("e2e_test_%s_%s_*", proxyType, composeMode))
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Copy necessary files to temp directory
	if err := copyTestFiles(tempDir, proxyType, composeMode); err != nil {
		os.RemoveAll(tempDir)
		t.Fatalf("Failed to copy test files: %v", err)
	}

	env := &TestEnvironment{
		WorkDir:     tempDir,
		ProxyType:   proxyType,
		ComposeMode: composeMode,
		Services:    getRequiredServices(proxyType),
		Cleanup: func() error {
			return os.RemoveAll(tempDir)
		},
	}

	return env
}

// StartServices starts the required services for testing
func (e *TestEnvironment) StartServices(ctx context.Context) error {
	var cmd *exec.Cmd
	
	if e.ComposeMode == "single" {
		// Single file mode with profiles
		args := []string{"docker-compose", "up", "-d"}
		if e.ProxyType != "standalone" {
			args = append(args, "--profile", e.ProxyType)
		}
		cmd = exec.CommandContext(ctx, args[0], args[1:]...)
	} else {
		// Separate file mode
		files := []string{
			filepath.Join(e.WorkDir, "docker-compose.core.yml"),
		}
		if e.ProxyType != "standalone" {
			files = append(files, filepath.Join(e.WorkDir, fmt.Sprintf("docker-compose.%s.yml", e.ProxyType)))
		}
		
		args := []string{"docker-compose"}
		for _, file := range files {
			args = append(args, "-f", file)
		}
		args = append(args, "up", "-d")
		cmd = exec.CommandContext(ctx, args[0], args[1:]...)
	}
	
	cmd.Dir = e.WorkDir
	return cmd.Run()
}

// StopServices stops all running services
func (e *TestEnvironment) StopServices(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker-compose", "down", "-v")
	cmd.Dir = e.WorkDir
	return cmd.Run()
}

// WaitForServices waits for services to be ready
func (e *TestEnvironment) WaitForServices(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		if e.areServicesReady(ctx) {
			return nil
		}
		time.Sleep(2 * time.Second)
	}
	
	return fmt.Errorf("services not ready within timeout")
}

// areServicesReady checks if all required services are ready
func (e *TestEnvironment) areServicesReady(ctx context.Context) bool {
	for _, service := range e.Services {
		if !e.isServiceReady(ctx, service) {
			return false
		}
	}
	return true
}

// isServiceReady checks if a specific service is ready
func (e *TestEnvironment) isServiceReady(ctx context.Context, service string) bool {
	cmd := exec.CommandContext(ctx, "docker-compose", "ps", "-q", service)
	cmd.Dir = e.WorkDir
	output, err := cmd.Output()
	if err != nil || len(output) == 0 {
		return false
	}
	
	// Check if container is running
	containerID := string(output)
	cmd = exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Running}}", containerID)
	output, err = cmd.Output()
	if err != nil {
		return false
	}
	
	return string(output) == "true\n"
}

// GetServiceURL returns the URL for a service
func (e *TestEnvironment) GetServiceURL(service string) string {
	switch service {
	case "crowdsec-manager":
		return "http://localhost:8080"
	case "traefik":
		return "http://localhost:8081"
	case "nginx":
		return "http://localhost:8082"
	case "caddy":
		return "http://localhost:8083"
	case "haproxy":
		return "http://localhost:8084"
	case "zoraxy":
		return "http://localhost:8085"
	default:
		return ""
	}
}

// copyTestFiles copies necessary files for testing
func copyTestFiles(destDir, proxyType, composeMode string) error {
	// Create test compose files
	files := map[string]string{
		"docker-compose.yml": generateSingleModeCompose(),
		"docker-compose.core.yml": generateCoreCompose(),
	}
	
	// Add proxy-specific compose files
	if proxyType != "standalone" {
		files[fmt.Sprintf("docker-compose.%s.yml", proxyType)] = generateProxyCompose(proxyType)
	}
	
	// Create .env file
	files[".env"] = generateEnvFile(proxyType, composeMode)
	
	for filename, content := range files {
		path := filepath.Join(destDir, filename)
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return err
		}
	}
	
	return nil
}

// getRequiredServices returns the list of services required for a proxy type
func getRequiredServices(proxyType string) []string {
	services := []string{"crowdsec", "crowdsec-manager"}
	
	if proxyType != "standalone" {
		services = append(services, proxyType)
	}
	
	return services
}

// generateSingleModeCompose generates a single-mode docker-compose.yml
func generateSingleModeCompose() string {
	return `version: '3.8'
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    profiles: ["crowdsec"]
    environment:
      - COLLECTIONS=crowdsecurity/traefik
    volumes:
      - ./config/crowdsec:/etc/crowdsec
      - crowdsec-data:/var/lib/crowdsec/data
    networks:
      - crowdsec-net

  crowdsec-manager:
    image: crowdsec-manager:test
    profiles: ["crowdsec"]
    ports:
      - "8080:8080"
    environment:
      - PROXY_TYPE=${PROXY_TYPE:-traefik}
      - COMPOSE_MODE=${COMPOSE_MODE:-single}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./data:/app/data
    networks:
      - crowdsec-net

  traefik:
    image: traefik:latest
    profiles: ["traefik"]
    ports:
      - "8081:80"
      - "8082:8080"
    command:
      - --api.insecure=true
      - --providers.docker=true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - crowdsec-net

  nginx:
    image: jc21/nginx-proxy-manager:latest
    profiles: ["nginx"]
    ports:
      - "8082:80"
      - "8083:81"
    volumes:
      - nginx-data:/data
      - nginx-letsencrypt:/etc/letsencrypt
    networks:
      - crowdsec-net

  caddy:
    image: caddy:latest
    profiles: ["caddy"]
    ports:
      - "8083:80"
      - "8084:2019"
    networks:
      - crowdsec-net

  haproxy:
    image: haproxy:latest
    profiles: ["haproxy"]
    ports:
      - "8084:80"
      - "8085:8404"
    networks:
      - crowdsec-net

  zoraxy:
    image: zoraxydocker/zoraxy:latest
    profiles: ["zoraxy"]
    ports:
      - "8085:80"
      - "8086:8000"
    networks:
      - crowdsec-net

volumes:
  crowdsec-data:
  nginx-data:
  nginx-letsencrypt:

networks:
  crowdsec-net:
    driver: bridge`
}

// generateCoreCompose generates a core-only docker-compose.yml
func generateCoreCompose() string {
	return `version: '3.8'
services:
  crowdsec:
    image: crowdsecurity/crowdsec:latest
    environment:
      - COLLECTIONS=crowdsecurity/traefik
    volumes:
      - ./config/crowdsec:/etc/crowdsec
      - crowdsec-data:/var/lib/crowdsec/data
    networks:
      - crowdsec-net

  crowdsec-manager:
    image: crowdsec-manager:test
    ports:
      - "8080:8080"
    environment:
      - PROXY_TYPE=${PROXY_TYPE:-traefik}
      - COMPOSE_MODE=${COMPOSE_MODE:-separate}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./data:/app/data
    networks:
      - crowdsec-net

volumes:
  crowdsec-data:

networks:
  crowdsec-net:
    driver: bridge`
}

// generateProxyCompose generates proxy-specific compose file
func generateProxyCompose(proxyType string) string {
	switch proxyType {
	case "traefik":
		return `version: '3.8'
services:
  traefik:
    image: traefik:latest
    ports:
      - "8081:80"
      - "8082:8080"
    command:
      - --api.insecure=true
      - --providers.docker=true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - crowdsec-net

networks:
  crowdsec-net:
    external: true`
	case "nginx":
		return `version: '3.8'
services:
  nginx:
    image: jc21/nginx-proxy-manager:latest
    ports:
      - "8082:80"
      - "8083:81"
    volumes:
      - nginx-data:/data
      - nginx-letsencrypt:/etc/letsencrypt
    networks:
      - crowdsec-net

volumes:
  nginx-data:
  nginx-letsencrypt:

networks:
  crowdsec-net:
    external: true`
	default:
		return fmt.Sprintf(`version: '3.8'
services:
  %s:
    image: %s:latest
    ports:
      - "8082:80"
    networks:
      - crowdsec-net

networks:
  crowdsec-net:
    external: true`, proxyType, proxyType)
	}
}

// generateEnvFile generates environment file for testing
func generateEnvFile(proxyType, composeMode string) string {
	return fmt.Sprintf(`PROXY_TYPE=%s
COMPOSE_MODE=%s
CROWDSEC_CONTAINER_NAME=crowdsec
MANAGER_CONTAINER_NAME=crowdsec-manager
`, proxyType, composeMode)
}