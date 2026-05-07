package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"crowdsec-manager/internal/cache"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/models"
)

const nonEmptyAlertsOutput = `[
  {
    "id": 123,
    "scenario": "crowdsecurity/http-probing",
    "created_at": "2026-05-06T14:51:43Z",
    "source": {"scope": "Ip", "value": "198.51.100.10"},
    "decisions": [{"origin": "crowdsec", "type": "ban"}]
  }
]`

func TestAlertsAnalysisCachesNonEmptyResult(t *testing.T) {
	ttlCache := cache.New()
	fake := &fakeDockerClient{
		perCall: []fakeStub{
			{out: nonEmptyAlertsOutput},
			{out: `[]`},
		},
	}

	first := performAlertsAnalysisRequest(t, alertsAnalysisRequestInput{
		Fake:   fake,
		Cache:  ttlCache,
		Target: "/alerts/analysis?since=7d",
	})
	second := performAlertsAnalysisRequest(t, alertsAnalysisRequestInput{
		Fake:   fake,
		Cache:  ttlCache,
		Target: "/alerts/analysis?since=7d",
	})

	if first.Data.Count != 1 || second.Data.Count != 1 {
		t.Fatalf("expected cached non-empty counts to stay at 1, got first=%d second=%d", first.Data.Count, second.Data.Count)
	}
	if calls := fake.recordedCalls(); len(calls) != 1 {
		t.Fatalf("expected one executor call due normal cache hit, got %d", len(calls))
	}
}

func TestAlertsAnalysisReturnsLastNonEmptyWhenLiveResultIsTransientlyEmpty(t *testing.T) {
	ttlCache := cache.New()
	fake := &fakeDockerClient{
		perCall: []fakeStub{
			{out: nonEmptyAlertsOutput},
			{out: `[]`},
		},
	}
	target := "/alerts/analysis?since=7d"

	first := performAlertsAnalysisRequest(t, alertsAnalysisRequestInput{
		Fake:   fake,
		Cache:  ttlCache,
		Target: target,
	})
	if first.Data.Count != 1 {
		t.Fatalf("expected first response to have one alert, got %d", first.Data.Count)
	}

	ttlCache.Set(cacheKeyForRequest(t, target), "expired", -time.Second)
	second := performAlertsAnalysisRequest(t, alertsAnalysisRequestInput{
		Fake:   fake,
		Cache:  ttlCache,
		Target: target,
	})

	if second.Data.Count != 1 {
		t.Fatalf("expected same-key empty live result to return last non-empty payload, got %d", second.Data.Count)
	}
	if calls := fake.recordedCalls(); len(calls) != 2 {
		t.Fatalf("expected second request to call executor after normal cache expiry, got %d calls", len(calls))
	}
}

func TestAlertsAnalysisReturnsRealEmptyWithoutLastNonEmpty(t *testing.T) {
	ttlCache := cache.New()
	fake := &fakeDockerClient{
		perCall: []fakeStub{
			{out: `[]`},
			{out: nonEmptyAlertsOutput},
		},
	}

	first := performAlertsAnalysisRequest(t, alertsAnalysisRequestInput{
		Fake:   fake,
		Cache:  ttlCache,
		Target: "/alerts/analysis?scenario=missing",
	})
	second := performAlertsAnalysisRequest(t, alertsAnalysisRequestInput{
		Fake:   fake,
		Cache:  ttlCache,
		Target: "/alerts/analysis?scenario=missing",
	})

	if first.Data.Count != 0 || len(first.Data.Alerts) != 0 {
		t.Fatalf("expected real empty first response, got count=%d alerts=%d", first.Data.Count, len(first.Data.Alerts))
	}
	if second.Data.Count != 0 || len(second.Data.Alerts) != 0 {
		t.Fatalf("expected short empty cache to return real empty response, got count=%d alerts=%d", second.Data.Count, len(second.Data.Alerts))
	}
	if calls := fake.recordedCalls(); len(calls) != 1 {
		t.Fatalf("expected empty response to be cached briefly, got %d executor calls", len(calls))
	}
}

func TestInspectAllowlistReturnsEmptyItemsArray(t *testing.T) {
	fake := &fakeDockerClient{stubOut: `{"name":"my_allowlist","description":"Trusted IPs"}`}
	cfg := &config.Config{CrowdsecContainerName: "crowdsec"}
	r := newTestRouter()
	r.GET("/allowlist/inspect/:name", inspectAllowlistWithExecutor(allowlistInspectHandlerInput{
		Executor: fake,
		Config:   cfg,
	}))

	req := httptest.NewRequest(http.MethodGet, "/allowlist/inspect/my_allowlist", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d body=%s", w.Code, w.Body.String())
	}

	var envelope struct {
		Success bool `json:"success"`
		Data    struct {
			Name  string                  `json:"name"`
			Items []models.AllowlistEntry `json:"items"`
			Count int                     `json:"count"`
		} `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if !envelope.Success {
		t.Fatalf("expected success response")
	}
	if envelope.Data.Name != "my_allowlist" {
		t.Fatalf("expected allowlist name, got %q", envelope.Data.Name)
	}
	if envelope.Data.Items == nil {
		t.Fatalf("expected items to serialize as an empty array, got nil")
	}
	if envelope.Data.Count != 0 {
		t.Fatalf("expected count 0, got %d", envelope.Data.Count)
	}
}

type alertsAnalysisEnvelope struct {
	Success bool `json:"success"`
	Data    struct {
		Alerts []map[string]interface{} `json:"alerts"`
		Count  int                      `json:"count"`
	} `json:"data"`
}

type alertsAnalysisRequestInput struct {
	Fake   *fakeDockerClient
	Cache  *cache.TTLCache
	Target string
}

func performAlertsAnalysisRequest(t *testing.T, input alertsAnalysisRequestInput) alertsAnalysisEnvelope {
	t.Helper()

	cfg := &config.Config{CrowdsecContainerName: "crowdsec", AlertListLimit: 100}
	r := newTestRouter()
	r.GET("/alerts/analysis", getAlertsAnalysisWithExecutor(alertAnalysisHandlerInput{
		Executor: input.Fake,
		Config:   cfg,
		Cache:    input.Cache,
	}))

	req := httptest.NewRequest(http.MethodGet, input.Target, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d body=%s", w.Code, w.Body.String())
	}

	var envelope alertsAnalysisEnvelope
	if err := json.NewDecoder(w.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return envelope
}
