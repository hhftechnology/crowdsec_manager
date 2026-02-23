package docker

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"crowdsec-manager/internal/logger"

	"github.com/docker/docker/client"
)

// HostInfo describes a configured Docker host
type HostInfo struct {
	ID       string `json:"id"`
	Endpoint string `json:"endpoint"`
	IsLocal  bool   `json:"is_local"`
}

// MultiHostClient manages connections to multiple Docker hosts
type MultiHostClient struct {
	mu       sync.RWMutex
	clients  map[string]*Client
	hosts    []HostInfo
	defaultID string
}

// NewMultiHostClient creates a MultiHostClient from a config string.
// Format: "id:endpoint,id:endpoint" e.g. "local:unix:///var/run/docker.sock,remote:tcp://192.168.1.10:2375"
// If hostsConfig is empty, falls back to a single default client using DOCKER_HOST env var.
func NewMultiHostClient(hostsConfig string) (*MultiHostClient, error) {
	mhc := &MultiHostClient{
		clients: make(map[string]*Client),
	}

	if hostsConfig == "" {
		// Fallback: single host from environment (DOCKER_HOST or default socket)
		c, err := NewClient()
		if err != nil {
			return nil, fmt.Errorf("failed to create default docker client: %w", err)
		}
		mhc.clients["local"] = c
		mhc.defaultID = "local"
		mhc.hosts = []HostInfo{{ID: "local", Endpoint: "unix:///var/run/docker.sock", IsLocal: true}}
		logger.Info("Multi-host Docker client initialized with single default host")
		return mhc, nil
	}

	// Parse "id:endpoint,id:endpoint" format
	entries := strings.Split(hostsConfig, ",")
	for i, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("invalid DOCKER_HOSTS entry %q: expected id:endpoint", entry)
		}

		hostID := strings.TrimSpace(parts[0])
		endpoint := strings.TrimSpace(parts[1])

		isLocal := strings.HasPrefix(endpoint, "unix://")

		cli, err := client.NewClientWithOpts(
			client.WithHost(endpoint),
			client.WithAPIVersionNegotiation(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create docker client for host %q (%s): %w", hostID, endpoint, err)
		}

		mhc.clients[hostID] = &Client{cli: cli, ctx: context.Background()}
		mhc.hosts = append(mhc.hosts, HostInfo{ID: hostID, Endpoint: endpoint, IsLocal: isLocal})

		if i == 0 {
			mhc.defaultID = hostID
		}

		logger.Info("Registered Docker host", "id", hostID, "endpoint", endpoint)
	}

	if len(mhc.clients) == 0 {
		return nil, fmt.Errorf("no valid Docker hosts configured in DOCKER_HOSTS")
	}

	logger.Info("Multi-host Docker client initialized", "hosts", len(mhc.clients), "default", mhc.defaultID)
	return mhc, nil
}

// GetClient returns the Docker client for the given host ID.
// Returns the default client if hostID is empty.
func (m *MultiHostClient) GetClient(hostID string) (*Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if hostID == "" {
		hostID = m.defaultID
	}

	c, ok := m.clients[hostID]
	if !ok {
		return nil, fmt.Errorf("unknown docker host: %q", hostID)
	}
	return c, nil
}

// DefaultClient returns the default Docker client
func (m *MultiHostClient) DefaultClient() *Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.clients[m.defaultID]
}

// ListHosts returns all configured host info with connectivity status
func (m *MultiHostClient) ListHosts() []HostInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]HostInfo, len(m.hosts))
	copy(result, m.hosts)
	return result
}

// DefaultHostID returns the default host identifier
func (m *MultiHostClient) DefaultHostID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.defaultID
}

// Close closes all Docker client connections
func (m *MultiHostClient) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, c := range m.clients {
		if err := c.Close(); err != nil {
			logger.Error("Failed to close Docker client", "host", id, "error", err)
		}
	}
}
