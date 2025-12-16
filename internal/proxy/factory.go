package proxy

import (
	"context"
	"fmt"
	"sync"
)

// AdapterFactory is a function that creates a new proxy adapter instance
type AdapterFactory func() ProxyAdapter

// Registry manages proxy adapter registration and creation
type Registry struct {
	mu        sync.RWMutex
	factories map[ProxyType]AdapterFactory
}

// NewRegistry creates a new proxy adapter registry
func NewRegistry() *Registry {
	return &Registry{
		factories: make(map[ProxyType]AdapterFactory),
	}
}

// Register registers a proxy adapter factory for a specific proxy type
func (r *Registry) Register(proxyType ProxyType, factory AdapterFactory) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if factory == nil {
		return fmt.Errorf("factory cannot be nil")
	}
	
	if _, exists := r.factories[proxyType]; exists {
		return fmt.Errorf("adapter for proxy type %s is already registered", proxyType)
	}
	
	r.factories[proxyType] = factory
	return nil
}

// Create creates a new proxy adapter instance for the specified type
func (r *Registry) Create(proxyType ProxyType) (ProxyAdapter, error) {
	r.mu.RLock()
	factory, exists := r.factories[proxyType]
	r.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("no adapter registered for proxy type: %s", proxyType)
	}
	
	return factory(), nil
}

// GetRegisteredTypes returns all registered proxy types
func (r *Registry) GetRegisteredTypes() []ProxyType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	types := make([]ProxyType, 0, len(r.factories))
	for proxyType := range r.factories {
		types = append(types, proxyType)
	}
	return types
}

// IsRegistered checks if a proxy type is registered
func (r *Registry) IsRegistered(proxyType ProxyType) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	_, exists := r.factories[proxyType]
	return exists
}

// Unregister removes a proxy adapter factory (mainly for testing)
func (r *Registry) Unregister(proxyType ProxyType) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	delete(r.factories, proxyType)
}

// Global registry instance
var globalRegistry = NewRegistry()

// RegisterAdapter registers a proxy adapter factory globally
func RegisterAdapter(proxyType ProxyType, factory AdapterFactory) error {
	return globalRegistry.Register(proxyType, factory)
}

// CreateAdapter creates a new proxy adapter instance from the global registry
func CreateAdapter(proxyType ProxyType) (ProxyAdapter, error) {
	return globalRegistry.Create(proxyType)
}

// GetRegisteredAdapterTypes returns all registered proxy types from the global registry
func GetRegisteredAdapterTypes() []ProxyType {
	return globalRegistry.GetRegisteredTypes()
}

// IsAdapterRegistered checks if a proxy type is registered in the global registry
func IsAdapterRegistered(proxyType ProxyType) bool {
	return globalRegistry.IsRegistered(proxyType)
}

// ProxyManager manages the lifecycle of proxy adapters
type ProxyManager struct {
	registry *Registry
	adapters map[ProxyType]ProxyAdapter
	mu       sync.RWMutex
}

// NewProxyManager creates a new proxy manager
func NewProxyManager(registry *Registry) *ProxyManager {
	if registry == nil {
		registry = globalRegistry
	}
	
	return &ProxyManager{
		registry: registry,
		adapters: make(map[ProxyType]ProxyAdapter),
	}
}

// GetAdapter gets or creates a proxy adapter for the specified type
func (pm *ProxyManager) GetAdapter(ctx context.Context, proxyType ProxyType, config *ProxyConfig) (ProxyAdapter, error) {
	pm.mu.RLock()
	adapter, exists := pm.adapters[proxyType]
	pm.mu.RUnlock()
	
	if exists {
		return adapter, nil
	}
	
	// Create new adapter
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	// Double-check after acquiring write lock
	if adapter, exists := pm.adapters[proxyType]; exists {
		return adapter, nil
	}
	
	// Create the adapter
	adapter, err := pm.registry.Create(proxyType)
	if err != nil {
		return nil, fmt.Errorf("failed to create adapter for %s: %w", proxyType, err)
	}
	
	// Initialize the adapter if config is provided
	if config != nil {
		if err := adapter.Initialize(ctx, config); err != nil {
			return nil, fmt.Errorf("failed to initialize adapter for %s: %w", proxyType, err)
		}
	}
	
	pm.adapters[proxyType] = adapter
	return adapter, nil
}

// RemoveAdapter removes a cached adapter (mainly for testing or reconfiguration)
func (pm *ProxyManager) RemoveAdapter(proxyType ProxyType) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	delete(pm.adapters, proxyType)
}

// GetCachedAdapter returns a cached adapter without creating a new one
func (pm *ProxyManager) GetCachedAdapter(proxyType ProxyType) (ProxyAdapter, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	adapter, exists := pm.adapters[proxyType]
	return adapter, exists
}

// ListCachedAdapters returns all currently cached adapters
func (pm *ProxyManager) ListCachedAdapters() map[ProxyType]ProxyAdapter {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	
	result := make(map[ProxyType]ProxyAdapter)
	for proxyType, adapter := range pm.adapters {
		result[proxyType] = adapter
	}
	return result
}

// ValidateProxyType checks if a proxy type string is valid
func ValidateProxyType(proxyType string) error {
	switch ProxyType(proxyType) {
	case ProxyTypeTraefik, ProxyTypeNginx, ProxyTypeCaddy, ProxyTypeHAProxy, ProxyTypeZoraxy, ProxyTypeStandalone:
		return nil
	default:
		return fmt.Errorf("invalid proxy type: %s", proxyType)
	}
}

// GetAllProxyTypes returns all available proxy types
func GetAllProxyTypes() []ProxyType {
	return []ProxyType{
		ProxyTypeTraefik,
		ProxyTypeNginx,
		ProxyTypeCaddy,
		ProxyTypeHAProxy,
		ProxyTypeZoraxy,
		ProxyTypeStandalone,
	}
}

// GetProxyTypeDescription returns a human-readable description of a proxy type
func GetProxyTypeDescription(proxyType ProxyType) string {
	descriptions := map[ProxyType]string{
		ProxyTypeTraefik:    "Traefik reverse proxy with full CrowdSec integration",
		ProxyTypeNginx:      "Nginx Proxy Manager with log parsing and bouncer support",
		ProxyTypeCaddy:      "Caddy web server with CrowdSec bouncer module",
		ProxyTypeHAProxy:    "HAProxy with SPOA bouncer integration",
		ProxyTypeZoraxy:     "Zoraxy reverse proxy (experimental support)",
		ProxyTypeStandalone: "CrowdSec only mode without reverse proxy integration",
	}
	
	if desc, exists := descriptions[proxyType]; exists {
		return desc
	}
	return fmt.Sprintf("Unknown proxy type: %s", proxyType)
}