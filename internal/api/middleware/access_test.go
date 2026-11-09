package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"crowdsec-manager/internal/api/handlers"
	"crowdsec-manager/internal/api/middleware"
	"crowdsec-manager/internal/logger"

	"github.com/gin-gonic/gin"
)

const testToken = "0123456789abcdef"

func init() {
	gin.SetMode(gin.TestMode)
	logger.Init("error", "")
}

func testRouter(allowed []string) *gin.Engine {
	router := gin.New()
	api := middleware.ProtectAPI(router, testToken, allowed)
	router.GET("/health", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	api.GET("/terminal/:container", handlers.TerminalSession(nil, allowed))
	return router
}

func perform(router http.Handler, method, target, host, origin, auth string, body string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, target, reader)
	req.Host = host
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestUnauthenticatedAPIAndTerminalAreRejected(t *testing.T) {
	router := testRouter(nil)

	session := perform(router, http.MethodGet, "/api/session", "manager.example", "", "", "")
	if session.Code != http.StatusUnauthorized {
		t.Fatalf("session status = %d, want 401; body %s", session.Code, session.Body.String())
	}

	terminal := perform(router, http.MethodGet, "/api/terminal/crowdsec", "manager.example", "", "", "")
	if terminal.Code != http.StatusUnauthorized {
		t.Fatalf("terminal status = %d, want 401; body %s", terminal.Code, terminal.Body.String())
	}

	wrong := perform(router, http.MethodGet, "/api/terminal/crowdsec", "manager.example", "", "Bearer not-the-token", "")
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, want 401", wrong.Code)
	}

	health := perform(router, http.MethodGet, "/health", "manager.example", "", "", "")
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d, want 200", health.Code)
	}
}

func TestCrossOriginAPIAndTerminalAreRejected(t *testing.T) {
	router := testRouter([]string{"https://app.example"})
	auth := "Bearer " + testToken

	api := perform(router, http.MethodGet, "/api/session", "manager.example", "https://evil.example", auth, "")
	if api.Code != http.StatusForbidden {
		t.Fatalf("api status = %d, want 403; body %s", api.Code, api.Body.String())
	}
	if got := api.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("forbidden response echoed origin %q", got)
	}

	terminal := perform(router, http.MethodGet, "/api/terminal/crowdsec", "manager.example", "https://evil.example", auth, "")
	if terminal.Code != http.StatusForbidden {
		t.Fatalf("terminal status = %d, want 403; body %s", terminal.Code, terminal.Body.String())
	}

	health := perform(router, http.MethodGet, "/health", "manager.example", "https://evil.example", "", "")
	if health.Code != http.StatusForbidden {
		t.Fatalf("health status = %d, want 403", health.Code)
	}

	preflight := perform(router, http.MethodOptions, "/api/terminal/crowdsec", "manager.example", "https://evil.example", "", "")
	if preflight.Code != http.StatusForbidden {
		t.Fatalf("preflight status = %d, want 403", preflight.Code)
	}
}

func TestSameOriginAndAllowlistedRequestsPassAuth(t *testing.T) {
	router := testRouter([]string{"https://app.example"})
	auth := "Bearer " + testToken

	same := perform(router, http.MethodGet, "/api/session", "manager.example", "https://manager.example", auth, "")
	if same.Code != http.StatusNoContent {
		t.Fatalf("same-origin status = %d, want 204; body %s", same.Code, same.Body.String())
	}

	listed := perform(router, http.MethodGet, "/api/session", "manager.example", "https://app.example", auth, "")
	if listed.Code != http.StatusNoContent {
		t.Fatalf("allowlisted status = %d, want 204; body %s", listed.Code, listed.Body.String())
	}
	if got := listed.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example" {
		t.Fatalf("allow-origin = %q", got)
	}

	noOrigin := perform(router, http.MethodGet, "/api/session", "manager.example", "", auth, "")
	if noOrigin.Code != http.StatusNoContent {
		t.Fatalf("no-origin status = %d, want 204", noOrigin.Code)
	}
}

func TestSessionCookieAuthenticatesLaterRequests(t *testing.T) {
	router := testRouter(nil)
	created := perform(router, http.MethodPost, "/api/session", "manager.example", "", "", `{"token":"`+testToken+`"}`)
	if created.Code != http.StatusNoContent {
		t.Fatalf("create status = %d, want 204; body %s", created.Code, created.Body.String())
	}
	cookie := created.Result().Cookies()
	if len(cookie) != 1 || cookie[0].Name != "csm_session" || !cookie[0].HttpOnly {
		t.Fatalf("cookie = %#v", cookie)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	req.Host = "manager.example"
	req.AddCookie(cookie[0])
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("cookie was rejected: %d %s", rec.Code, rec.Body.String())
	}
}

func TestTerminalUpgradeRejectsOtherOrigin(t *testing.T) {
	router := gin.New()
	router.GET("/api/terminal/:container", handlers.TerminalSession(nil, []string{"https://app.example"}))

	req := httptest.NewRequest(http.MethodGet, "/api/terminal/crowdsec", nil)
	req.Host = "manager.example"
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("upgrade status = %d, want 403; body %s", rec.Code, rec.Body.String())
	}
}

func TestOriginPermitted(t *testing.T) {
	allowed := []string{"https://app.example"}
	cases := []struct {
		origin string
		host   string
		want   bool
	}{
		{origin: "", host: "manager.example", want: true},
		{origin: "https://manager.example", host: "manager.example", want: true},
		{origin: "http://localhost:8080", host: "localhost:8080", want: true},
		{origin: "http://localhost:5173", host: "localhost:8080", want: false},
		{origin: "https://evil.example", host: "manager.example", want: false},
		{origin: "https://app.example", host: "manager.example", want: true},
		{origin: "https://manager.example", host: "manager.example:8443", want: false},
	}
	for _, tc := range cases {
		if got := middleware.OriginPermitted(tc.origin, tc.host, allowed); got != tc.want {
			t.Errorf("OriginPermitted(%q, %q) = %v, want %v", tc.origin, tc.host, got, tc.want)
		}
	}
}
