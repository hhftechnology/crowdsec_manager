package cache

import (
	"sync"
	"time"
)

type entry struct {
	value     interface{}
	expiresAt time.Time
}

// TTLCache is a simple in-memory cache with per-key TTL expiration.
// Safe for concurrent use.
type TTLCache struct {
	mu    sync.RWMutex
	items map[string]entry
}

// New creates a new TTLCache.
func New() *TTLCache {
	return &TTLCache{
		items: make(map[string]entry),
	}
}

// Get returns the cached value and true if the key exists and hasn't expired.
func (c *TTLCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()

	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.value, true
}

// Set stores a value with the given TTL.
func (c *TTLCache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	c.items[key] = entry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
	c.mu.Unlock()
}
