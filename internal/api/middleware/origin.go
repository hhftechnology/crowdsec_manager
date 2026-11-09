package middleware

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

// OriginPermitted reports whether origin may call this server.
// An empty Origin header is permitted: non-browser clients and same-origin
// navigations do not send one. A browser Origin is permitted when its host
// matches the request Host, or when it is listed in allowed.
func OriginPermitted(origin, requestHost string, allowed []string) bool {
	if origin == "" {
		return true
	}
	if originMatchesRequestHost(origin, requestHost) {
		return true
	}
	normalized := strings.TrimRight(origin, "/")
	for _, candidate := range allowed {
		if strings.EqualFold(normalized, strings.TrimRight(candidate, "/")) {
			return true
		}
	}
	return false
}

func originMatchesRequestHost(origin, requestHost string) bool {
	parsed, err := url.Parse(origin)
	if err != nil || parsed.Hostname() == "" {
		return false
	}
	hostName, hostPort := splitHostPort(requestHost)
	if !strings.EqualFold(parsed.Hostname(), hostName) {
		return false
	}
	originPort := parsed.Port()
	if originPort == "" {
		switch parsed.Scheme {
		case "https":
			originPort = "443"
		case "http":
			originPort = "80"
		default:
			originPort = ""
		}
	}
	if hostPort == "" {
		hostPort = originPort
	}
	return originPort != "" && originPort == hostPort
}

func splitHostPort(hostport string) (string, string) {
	name, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, ""
	}
	return name, port
}

// OriginGuard rejects browser requests whose Origin is not the request host
// and is not in allowed. Permitted cross-origin requests get a specific
// Access-Control-Allow-Origin echo so cookies can be used from that origin.
func OriginGuard(allowed []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			c.Next()
			return
		}
		c.Header("Vary", "Origin")
		if !OriginPermitted(origin, c.Request.Host, allowed) {
			c.AbortWithStatusJSON(http.StatusForbidden, models.Response{
				Success: false,
				Error:   "origin not allowed",
			})
			return
		}
		header := c.Writer.Header()
		header.Set("Access-Control-Allow-Origin", origin)
		header.Set("Access-Control-Allow-Credentials", "true")
		header.Set("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Docker-Host")
		header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		header.Set("Access-Control-Max-Age", "43200")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
