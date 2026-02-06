package middleware

import (
	"fmt"

	"crowdsec-manager/internal/logger"

	"github.com/gin-gonic/gin"
)

// Deprecated returns middleware that marks an endpoint as deprecated.
// It adds standard HTTP deprecation headers and logs a warning on each call.
// The replacement parameter should be the full path of the new endpoint
// (e.g., "/api/whitelist/proxy").
func Deprecated(replacement string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Deprecation", "true")
		c.Header("Sunset", "2026-08-01")
		c.Header("Link", fmt.Sprintf("<%s>; rel=\"successor-version\"", replacement))

		logger.Warn("Deprecated endpoint called",
			"path", c.Request.URL.Path,
			"method", c.Request.Method,
			"replacement", replacement,
			"client_ip", c.ClientIP(),
		)

		c.Next()
	}
}
