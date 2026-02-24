package middleware

import (
	"net/http"
	"sync"
	"time"

	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// visitor tracks request counts for a single IP address using a sliding window.
type visitor struct {
	mu        sync.Mutex
	tokens    int
	lastReset time.Time
}

// rateLimiter holds the per-IP visitor map and configuration.
type rateLimiter struct {
	visitors          sync.Map // map[string]*visitor
	requestsPerMinute int
	cleanupInterval   time.Duration
	done              chan struct{}
}

// newRateLimiter creates a rate limiter and starts a background cleanup goroutine
// to evict stale entries from the visitor map.
func newRateLimiter(requestsPerMinute int) *rateLimiter {
	rl := &rateLimiter{
		requestsPerMinute: requestsPerMinute,
		cleanupInterval:   5 * time.Minute,
		done:              make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// allow checks whether the given IP is allowed to make another request.
// It refills tokens based on elapsed time (token-bucket algorithm with 1-minute window).
func (rl *rateLimiter) allow(ip string) bool {
	val, _ := rl.visitors.LoadOrStore(ip, &visitor{
		tokens:    rl.requestsPerMinute,
		lastReset: time.Now(),
	})

	v := val.(*visitor)
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(v.lastReset)

	// Refill tokens proportionally to elapsed time
	if elapsed >= time.Minute {
		v.tokens = rl.requestsPerMinute
		v.lastReset = now
	} else {
		// Partial refill based on fraction of minute elapsed
		refill := int(elapsed.Seconds() / 60.0 * float64(rl.requestsPerMinute))
		if refill > 0 {
			v.tokens += refill
			if v.tokens > rl.requestsPerMinute {
				v.tokens = rl.requestsPerMinute
			}
			v.lastReset = now
		}
	}

	if v.tokens <= 0 {
		return false
	}

	v.tokens--
	return true
}

// cleanup periodically removes stale visitor entries that have not been
// seen for more than 2 minutes to prevent unbounded memory growth.
func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			threshold := time.Now().Add(-2 * time.Minute)
			rl.visitors.Range(func(key, value any) bool {
				v := value.(*visitor)
				v.mu.Lock()
				stale := v.lastReset.Before(threshold)
				v.mu.Unlock()
				if stale {
					rl.visitors.Delete(key)
				}
				return true
			})
		case <-rl.done:
			return
		}
	}
}

// RateLimiter returns a Gin middleware that limits requests per IP address.
// When the limit is exceeded, it returns HTTP 429 Too Many Requests.
func RateLimiter(requestsPerMinute int) gin.HandlerFunc {
	rl := newRateLimiter(requestsPerMinute)

	return func(c *gin.Context) {
		ip := c.ClientIP()

		if !rl.allow(ip) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, models.Response{
				Success: false,
				Error:   "Rate limit exceeded. Please try again later.",
			})
			return
		}

		c.Next()
	}
}
