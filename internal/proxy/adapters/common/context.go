package common

import (
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
	"crowdsec-manager/internal/proxy"
	"fmt"
)

// AdapterDependencies captures shared objects every adapter needs to operate.
type AdapterDependencies struct {
	Client        *docker.Client
	ContainerName string
	Config        *config.Config
}

// BuildAdapterDependencies normalizes proxy adapter setup (docker client, container name, base config).
func BuildAdapterDependencies(cfg *proxy.ProxyConfig, defaultContainer string) (*AdapterDependencies, error) {
	if cfg == nil {
		return nil, fmt.Errorf("proxy config is required")
	}

	client, ok := cfg.DockerClient.(*docker.Client)
	if !ok || client == nil {
		return nil, fmt.Errorf("invalid docker client type")
	}

	containerName := cfg.ContainerName
	if containerName == "" {
		containerName = defaultContainer
	}

	baseCfg := &config.Config{
		// Base defaults reused by feature managers; callers can override as needed.
		CrowdsecContainerName: "crowdsec",
		TraefikContainerName:  containerName,
	}

	return &AdapterDependencies{
		Client:        client,
		ContainerName: containerName,
		Config:        baseCfg,
	}, nil
}

// CheckContainerRunning standardizes container health checks before adapter-specific probes.
func CheckContainerRunning(client *docker.Client, containerName, adapterName string) (*models.HealthCheckItem, error) {
	if client == nil {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: fmt.Sprintf("%s adapter not properly initialized", adapterName),
			Error:   "Docker client is nil",
		}, nil
	}

	isRunning, err := client.IsContainerRunning(containerName)
	if err != nil {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: fmt.Sprintf("Failed to check %s container status", adapterName),
			Error:   fmt.Sprintf("Container check error: %v", err),
		}, nil
	}

	if !isRunning {
		return &models.HealthCheckItem{
			Status:  "unhealthy",
			Message: fmt.Sprintf("%s container is not running", adapterName),
			Details: fmt.Sprintf("Container '%s' is stopped or not found", containerName),
		}, nil
	}

	return nil, nil
}

// BuildHealthyStatus returns a consistent healthy response payload with optional metrics.
func BuildHealthyStatus(adapterName string, proxyType proxy.ProxyType, containerName string, features []proxy.Feature, extraMetrics map[string]interface{}) *models.HealthCheckItem {
	metrics := map[string]interface{}{
		"proxy_type":         proxyType,
		"container_name":     containerName,
		"supported_features": features,
	}

	for k, v := range extraMetrics {
		metrics[k] = v
	}

	return &models.HealthCheckItem{
		Status:  "healthy",
		Message: fmt.Sprintf("%s container is running", adapterName),
		Details: fmt.Sprintf("Container: %s", containerName),
		Metrics: metrics,
	}
}
