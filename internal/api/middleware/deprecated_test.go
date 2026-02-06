package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"crowdsec-manager/internal/logger"

	"github.com/gin-gonic/gin"
)

func init() {
	// Initialize logger for tests to avoid nil pointer panics
	logger.Init("error", "")
}

func TestDeprecated_SetsHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	r.GET("/old-endpoint",
		Deprecated("/api/new-endpoint"),
		func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"ok": true})
		},
	)

	c.Request = httptest.NewRequest(http.MethodGet, "/old-endpoint", nil)
	r.ServeHTTP(w, c.Request)

	// Handler should still execute
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	// Check deprecation headers
	if dep := w.Header().Get("Deprecation"); dep != "true" {
		t.Errorf("expected Deprecation header to be 'true', got %q", dep)
	}

	if sunset := w.Header().Get("Sunset"); sunset != "2026-08-01" {
		t.Errorf("expected Sunset header to be '2026-08-01', got %q", sunset)
	}

	link := w.Header().Get("Link")
	if link == "" {
		t.Error("expected Link header to be set")
	}
	expected := `</api/new-endpoint>; rel="successor-version"`
	if link != expected {
		t.Errorf("expected Link header %q, got %q", expected, link)
	}
}

func TestDeprecated_PassesThrough(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, r := gin.CreateTestContext(w)

	handlerCalled := false
	r.POST("/deprecated",
		Deprecated("/api/replacement"),
		func(c *gin.Context) {
			handlerCalled = true
			c.JSON(http.StatusCreated, gin.H{"created": true})
		},
	)

	c.Request = httptest.NewRequest(http.MethodPost, "/deprecated", nil)
	r.ServeHTTP(w, c.Request)

	if !handlerCalled {
		t.Error("handler should have been called despite deprecation")
	}

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d", w.Code)
	}
}
