package proxy

import (
	"log/slog"
	"sync"
)

var (
	mu       sync.RWMutex
	adapters = make(map[ProxyType]ProxyAdapter)
)

// Register adds an adapter to the global registry.
func Register(adapter ProxyAdapter) {
	mu.Lock()
	defer mu.Unlock()
	adapters[adapter.Type()] = adapter
	slog.Info("proxy adapter registered", "type", adapter.Type(), "name", adapter.Name())
}

// Get retrieves a registered adapter by proxy type.
func Get(pt ProxyType) (ProxyAdapter, bool) {
	mu.RLock()
	defer mu.RUnlock()
	a, ok := adapters[pt]
	return a, ok
}

// Available returns a list of all registered proxy types.
func Available() []ProxyType {
	mu.RLock()
	defer mu.RUnlock()
	types := make([]ProxyType, 0, len(adapters))
	for pt := range adapters {
		types = append(types, pt)
	}
	return types
}
