// Package middleware provides reusable Gin middleware for the CrowdSec Manager API.
package middleware

import (
	"fmt"
	"net/http"

	"crowdsec-manager/internal/api/dto"
	"crowdsec-manager/internal/proxy"

	"github.com/gin-gonic/gin"
)

// RequireFeature returns middleware that blocks requests if the given proxy feature
// is not supported by the current proxy adapter. This eliminates scattered nil-checks
// in individual handlers.
func RequireFeature(adapter proxy.ProxyAdapter, feature proxy.Feature) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !proxy.IsFeatureSupported(adapter.Type(), feature) {
			c.JSON(http.StatusBadRequest, dto.ErrMsg(
				fmt.Sprintf("%s is not supported for %s proxy", feature, adapter.Type()),
			))
			c.Abort()
			return
		}
		c.Next()
	}
}
