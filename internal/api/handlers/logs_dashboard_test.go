package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"crowdsec-manager/internal/cache"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
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
		{"7d", true, models.Range7d},
		{"all", true, models.RangeAll},
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
	if rangeDuration(models.Range7d) != 7*24*time.Hour {
		t.Fatal("7d should be 7 days")
	}
	if rangeDuration(models.RangeAll) != 3650*24*time.Hour {
		t.Fatal("all should be 3650 days")
	}
	if rangeDuration("") != time.Hour {
		t.Fatal("default should be 1h")
	}
}

func TestRangeTailMap_AllPresetsCovered(t *testing.T) {
	for _, r := range []models.DashboardRange{models.Range5m, models.Range1h, models.Range6h, models.Range24h, models.Range7d, models.RangeAll} {
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

func TestUpdateLogProcessing_DisableInvalidatesDashboardCache(t *testing.T) {
	db := newDashboardTestDB(t)
	ttlCache := cache.New()
	ttlCache.Set(serviceDashboardCachePrefix+"traefik:test", "stale", time.Hour)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/logs/processing", GetLogProcessing(db))
	r.PUT("/logs/processing", UpdateLogProcessing(db, ttlCache))

	req := httptest.NewRequest(http.MethodPut, "/logs/processing", bytes.NewBufferString(`{"enabled":false}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	settings, err := db.GetSettings()
	if err != nil {
		t.Fatalf("get settings: %v", err)
	}
	if settings.LogProcessingEnabled {
		t.Fatal("expected log processing to be disabled")
	}
	if _, ok := ttlCache.Get(serviceDashboardCachePrefix + "traefik:test"); ok {
		t.Fatal("expected dashboard cache to be invalidated")
	}

	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/logs/processing", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from get, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestAnalyzeServiceDashboard_LogProcessingDisabledSkipsReads(t *testing.T) {
	db := newDashboardTestDB(t)
	settings, err := db.GetSettings()
	if err != nil {
		t.Fatalf("get settings: %v", err)
	}
	settings.LogProcessingEnabled = false
	if err := db.UpdateSettings(settings); err != nil {
		t.Fatalf("update settings: %v", err)
	}

	reader := &fakeDashboardReader{}
	w := runDashboardRequest(t, dashboardRequestInput{Reader: reader, Database: db, Service: "traefik", RawQuery: "range=1h"})
	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d — body: %s", w.Code, w.Body.String())
	}
	if reader.execCalls != 0 || reader.logCalls != 0 {
		t.Fatalf("disabled log processing must skip Docker reads; exec=%d logs=%d", reader.execCalls, reader.logCalls)
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
	Database *database.Database
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
		Reader:   input.Reader,
		Database: input.Database,
		Config:   cfg,
		Cache:    input.Cache,
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

func newDashboardTestDB(t *testing.T) *database.Database {
	t.Helper()
	db, err := database.New(t.TempDir() + "/settings.db")
	if err != nil {
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
