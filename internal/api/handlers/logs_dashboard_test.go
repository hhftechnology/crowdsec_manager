package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"crowdsec-manager/internal/cache"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/models"

	"github.com/gin-gonic/gin"
)

func TestParseDashboardRange(t *testing.T) {
	cases := []struct {
		in       string
		wantOK   bool
		wantNorm models.DashboardRange
	}{
		{"5m", true, models.Range5m},
		{"1h", true, models.Range1h},
		{"6h", true, models.Range6h},
		{"24h", true, models.Range24h},
		{"", false, ""},
		{"7m", false, ""},
		{"forever", false, ""},
	}
	for _, tc := range cases {
		got, ok := parseDashboardRange(tc.in)
		if ok != tc.wantOK || got != tc.wantNorm {
			t.Fatalf("parseDashboardRange(%q) = (%q,%v), want (%q,%v)", tc.in, got, ok, tc.wantNorm, tc.wantOK)
		}
	}
}

func TestRangeDuration(t *testing.T) {
	if rangeDuration(models.Range5m) != 5*time.Minute {
		t.Fatal("5m should be 5 minutes")
	}
	if rangeDuration(models.Range1h) != time.Hour {
		t.Fatal("1h should be 1 hour")
	}
	if rangeDuration(models.Range6h) != 6*time.Hour {
		t.Fatal("6h should be 6 hours")
	}
	if rangeDuration(models.Range24h) != 24*time.Hour {
		t.Fatal("24h should be 24 hours")
	}
	if rangeDuration("") != time.Hour {
		t.Fatal("default should be 1h")
	}
}

func TestRangeTailMap_AllPresetsCovered(t *testing.T) {
	for _, r := range []models.DashboardRange{models.Range5m, models.Range1h, models.Range6h, models.Range24h} {
		if rangeTailMap[r] == "" {
			t.Fatalf("range %s missing from rangeTailMap", r)
		}
	}
}

func TestGeoAdapter_NilResolverReturnsFalse(t *testing.T) {
	a := geoAdapter{r: nil}
	if _, ok := a.Lookup("8.8.8.8"); ok {
		t.Fatal("nil resolver adapter must return ok=false")
	}
}

func TestAnalyzeServiceDashboard_CachesIdenticalRequest(t *testing.T) {
	ttlCache := cache.New()
	reader := &fakeDashboardReader{}

	w := runDashboardRequest(t, dashboardRequestInput{Reader: reader, Cache: ttlCache, Service: "crowdsec", RawQuery: "range=1h"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	w = runDashboardRequest(t, dashboardRequestInput{Reader: reader, Cache: ttlCache, Service: "crowdsec", RawQuery: "range=1h"})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	if reader.logCalls != 1 {
		t.Fatalf("expected one log read after cache hit, got %d", reader.logCalls)
	}
}

func TestAnalyzeServiceDashboard_ChangedRangeMissesCache(t *testing.T) {
	ttlCache := cache.New()
	reader := &fakeDashboardReader{}

	runDashboardRequest(t, dashboardRequestInput{Reader: reader, Cache: ttlCache, Service: "crowdsec", RawQuery: "range=1h"})
	runDashboardRequest(t, dashboardRequestInput{Reader: reader, Cache: ttlCache, Service: "crowdsec", RawQuery: "range=5m"})
	if reader.logCalls != 2 {
		t.Fatalf("expected changed range to miss cache, got %d log reads", reader.logCalls)
	}
}

func TestAnalyzeServiceDashboard_ChangedHostMissesCache(t *testing.T) {
	ttlCache := cache.New()
	reader := &fakeDashboardReader{}

	runDashboardRequest(t, dashboardRequestInput{Reader: reader, Cache: ttlCache, Service: "crowdsec", RawQuery: "range=1h", Host: "alpha"})
	runDashboardRequest(t, dashboardRequestInput{Reader: reader, Cache: ttlCache, Service: "crowdsec", RawQuery: "range=1h", Host: "beta"})
	if reader.logCalls != 2 {
		t.Fatalf("expected changed host to miss cache, got %d log reads", reader.logCalls)
	}
}

func TestAnalyzeServiceDashboard_ChangedServiceMissesCache(t *testing.T) {
	ttlCache := cache.New()
	reader := &fakeDashboardReader{}

	runDashboardRequest(t, dashboardRequestInput{Reader: reader, Cache: ttlCache, Service: "crowdsec", RawQuery: "range=1h"})
	runDashboardRequest(t, dashboardRequestInput{Reader: reader, Cache: ttlCache, Service: "traefik", RawQuery: "range=1h"})
	if reader.logCalls != 2 {
		t.Fatalf("expected changed service to miss cache, got %d log reads", reader.logCalls)
	}
}

type fakeDashboardReader struct {
	execCalls int
	logCalls  int
	execOut   string
	execErr   error
	logOut    string
	logErr    error
}

func (f *fakeDashboardReader) ExecCommand(containerName string, cmd []string) (string, error) {
	f.execCalls++
	return f.execOut, f.execErr
}

func (f *fakeDashboardReader) GetContainerLogs(containerName string, tail string) (string, error) {
	f.logCalls++
	return f.logOut, f.logErr
}

type dashboardRequestInput struct {
	Reader   *fakeDashboardReader
	Cache    *cache.TTLCache
	Service  string
	RawQuery string
	Host     string
}

func runDashboardRequest(t *testing.T, input dashboardRequestInput) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)

	cfg := &config.Config{
		CrowdsecContainerName: "crowdsec",
		TraefikContainerName:  "traefik",
	}
	r := gin.New()
	r.GET("/logs/:service/dashboard", analyzeServiceDashboardWithReader(serviceDashboardHandlerInput{
		Reader: input.Reader,
		Config: cfg,
		Cache:  input.Cache,
	}))

	target := "/logs/" + input.Service + "/dashboard"
	if input.RawQuery != "" {
		target += "?" + input.RawQuery
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if input.Host != "" {
		req.Header.Set("X-Docker-Host", input.Host)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}
