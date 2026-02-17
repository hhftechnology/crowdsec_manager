package proxy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/crowdsecurity/crowdsec-manager/internal/config"
	"github.com/crowdsecurity/crowdsec-manager/internal/database"
	"github.com/crowdsecurity/crowdsec-manager/internal/docker"
)

// Manager orchestrates proxy adapter lifecycle.
type Manager struct {
	adapter ProxyAdapter
	config  *config.Config
	docker  *docker.Client
	db      *database.Database
}

// NewManager creates a new proxy manager.
func NewManager(cfg *config.Config, dockerClient *docker.Client, db *database.Database) *Manager {
	return &Manager{
		config: cfg,
		docker: dockerClient,
		db:     db,
	}
}

// Initialize resolves the proxy type, retrieves the adapter from the registry,
// and initializes it.
func (m *Manager) Initialize(ctx context.Context) error {
	pt := Resolve(ctx, m.config.ProxyType, m.docker)
	adapter, ok := Get(pt)
	if !ok {
		return fmt.Errorf("no adapter registered for proxy type %q", pt)
	}

	initCfg := InitConfig{
		Docker: m.docker,
		Config: m.config,
		DB:     m.db,
	}
	if err := adapter.Initialize(ctx, initCfg); err != nil {
		return fmt.Errorf("initialize adapter %q: %w", pt, err)
	}

	m.adapter = adapter
	slog.Info("proxy manager initialized", "type", pt, "adapter", adapter.Name())
	return nil
}

// Adapter returns the active proxy adapter.
func (m *Manager) Adapter() ProxyAdapter {
	return m.adapter
}

// ProxyType returns the active proxy type.
func (m *Manager) ProxyType() ProxyType {
	if m.adapter == nil {
		return ProxyStandalone
	}
	return m.adapter.Type()
}

// SupportedFeatures returns the features of the active adapter.
func (m *Manager) SupportedFeatures() []Feature {
	if m.adapter == nil {
		return nil
	}
	return m.adapter.SupportedFeatures()
}
