package diagnostics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"crowdsec-manager/internal/config"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestDiagnosticsDisabledReturnsNotFound(t *testing.T) {
	router := newDiagnosticsTestRouter(&config.Config{})
	recorder := performDiagnosticsRequest(router, "127.0.0.1:1234")

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("expected disabled diagnostics to return 404, got %d", recorder.Code)
	}
}

func TestDiagnosticsEnabledAllowsLocalRuntimeStats(t *testing.T) {
	router := newDiagnosticsTestRouter(&config.Config{EnableProfiling: true})
	recorder := performDiagnosticsRequest(router, "127.0.0.1:1234")

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected local diagnostics to return 200, got %d", recorder.Code)
	}
}

func TestDiagnosticsEnabledRejectsRemoteByDefault(t *testing.T) {
	router := newDiagnosticsTestRouter(&config.Config{EnableProfiling: true})
	recorder := performDiagnosticsRequest(router, "198.51.100.10:1234")

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected remote diagnostics to return 403, got %d", recorder.Code)
	}
}

func TestDiagnosticsEnabledAllowsRemote(t *testing.T) {
	router := newDiagnosticsTestRouter(&config.Config{EnableProfiling: true, ProfilingAllowRemote: true})
	recorder := performDiagnosticsRequest(router, "198.51.100.10:1234")

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected remote diagnostics to return 200 when allowed, got %d", recorder.Code)
	}
}

func newDiagnosticsTestRouter(cfg *config.Config) *gin.Engine {
	router := gin.New()
	RegisterRoutes(router.Group("/api"), cfg)
	return router
}

func performDiagnosticsRequest(router *gin.Engine, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/debug/runtime", nil)
	req.RemoteAddr = remoteAddr
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, req)
	return recorder
}
