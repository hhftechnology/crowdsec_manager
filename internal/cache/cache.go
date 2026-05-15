package cache

import (
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxEntries      = 512
	defaultCleanupInterval = time.Minute
)

type entry struct {
	value     interface{}
	expiresAt time.Time
}

// Options configures TTLCache memory bounds and cleanup cadence.
type Options struct {
	MaxEntries      int
	CleanupInterval time.Duration
}

// TTLCache is a simple in-memory cache with per-key TTL expiration.
// Safe for concurrent use.
type TTLCache struct {
	mu       sync.RWMutex
	items    map[string]entry
	maxItems int
	stop     chan struct{}
	stopOnce sync.Once
}

// New creates a new TTLCache.
func New(options ...Options) *TTLCache {
	opts := Options{
		MaxEntries:      defaultMaxEntries,
		CleanupInterval: defaultCleanupInterval,
	}
	if len(options) > 0 {
		opts = options[0]
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = defaultMaxEntries
	}
	if opts.CleanupInterval <= 0 {
		opts.CleanupInterval = defaultCleanupInterval
	}

	cache := &TTLCache{
		items:    make(map[string]entry),
		maxItems: opts.MaxEntries,
		stop:     make(chan struct{}),
	}
	go cache.cleanupExpired(opts.CleanupInterval)
	return cache
}

// Get returns the cached value and true if the key exists and hasn't expired.
func (c *TTLCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	e, ok := c.items[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}
	if time.Now().After(e.expiresAt) {
		c.mu.Lock()
		if current, exists := c.items[key]; exists && time.Now().After(current.expiresAt) {
			delete(c.items, key)
		}
		c.mu.Unlock()
		return nil, false
	}
	return e.value, true
}

// Set stores a value with the given TTL.
func (c *TTLCache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	now := time.Now()
	c.evictExpiredLocked(now)
	if _, exists := c.items[key]; !exists && len(c.items) >= c.maxItems {
		c.evictOldestLocked()
	}
	c.items[key] = entry{
		value:     value,
		expiresAt: now.Add(ttl),
	}
	c.mu.Unlock()
}

// DeletePrefix removes all cached entries whose key starts with prefix.
func (c *TTLCache) DeletePrefix(prefix string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key := range c.items {
		if strings.HasPrefix(key, prefix) {
			delete(c.items, key)
		}
	}
}

// Stop shuts down the cache cleanup goroutine.
func (c *TTLCache) Stop() {
	c.stopOnce.Do(func() {
		close(c.stop)
	})
}

func (c *TTLCache) cleanupExpired(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			c.evictExpiredLocked(time.Now())
			c.mu.Unlock()
		case <-c.stop:
			return
		}
	}
}

func (c *TTLCache) evictExpiredLocked(now time.Time) {
	for key, item := range c.items {
		if now.After(item.expiresAt) {
			delete(c.items, key)
		}
	}
}

func (c *TTLCache) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true
	for key, item := range c.items {
		if first || item.expiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = item.expiresAt
			first = false
		}
	}
	if oldestKey != "" {
		delete(c.items, oldestKey)
	}
}
