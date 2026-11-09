package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

const sessionCookieName = "csm_session"

// TokenMatches compares a presented secret with the configured API token.
// Both sides are hashed first so the comparison does not leak the length.
func TokenMatches(got, want string) bool {
	if got == "" || want == "" {
		return false
	}
	sumGot := sha256.Sum256([]byte(got))
	sumWant := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(sumGot[:], sumWant[:]) == 1
}

func bearerToken(header string) string {
	const scheme = "bearer "
	if len(header) < len(scheme) || !strings.EqualFold(header[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(header[len(scheme):])
}

func presentedToken(c *gin.Context) string {
	if token := bearerToken(c.GetHeader("Authorization")); token != "" {
		return token
	}
	cookie, err := c.Cookie(sessionCookieName)
	if err != nil {
		return ""
	}
	return cookie
}

// RequireAuth rejects /api requests that do not present API_TOKEN as a
// Bearer credential or the session cookie set by CreateSession.
func RequireAuth(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !TokenMatches(presentedToken(c), token) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.Response{
				Success: false,
				Error:   "unauthorized",
			})
			return
		}
		c.Next()
	}
}

// CreateSession checks API_TOKEN and stores it in an HttpOnly cookie so
// same-origin browser calls, including WebSocket and EventSource, can
// authenticate without putting the secret in the query string.
func CreateSession(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var body struct {
			Token string `json:"token"`
		}
		_ = c.ShouldBindJSON(&body)
		presented := strings.TrimSpace(body.Token)
		if presented == "" {
			presented = bearerToken(c.GetHeader("Authorization"))
		}
		if !TokenMatches(presented, token) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, models.Response{
				Success: false,
				Error:   "unauthorized",
			})
			return
		}
		secure := c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
		c.SetSameSite(http.SameSiteStrictMode)
		c.SetCookie(sessionCookieName, token, 0, "/", "", secure, true)
		c.Header("Cache-Control", "no-store")
		c.Status(http.StatusNoContent)
	}
}

// SessionStatus is a credential probe for the web UI. The auth middleware
// has already accepted the request by the time this runs.
func SessionStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Status(http.StatusNoContent)
	}
}

// ProtectAPI installs the origin gate on router and returns the /api group
// with rate limiting and authentication. POST /api/session is the only /api
// route that does not require an existing credential; it checks the token
// itself. /health is left for the caller to register and stays
// unauthenticated, but it still rejects a disallowed Origin.
func ProtectAPI(router *gin.Engine, token string, allowedOrigins []string) *gin.RouterGroup {
	router.Use(OriginGuard(allowedOrigins))
	api := router.Group("/api")
	api.Use(RateLimiter(100))
	api.POST("/session", CreateSession(token))
	api.Use(RequireAuth(token))
	api.GET("/session", SessionStatus())
	return api
}
