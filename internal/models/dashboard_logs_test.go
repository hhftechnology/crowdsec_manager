package models

import (
	"encoding/json"
	"testing"
)

func TestTraefikDashboard_JSONRoundTrip(t *testing.T) {
	avg := 12.5
	in := TraefikDashboard{
		Range:         Range1h,
		Format:        "json",
		GeneratedAt:   "2026-05-07T10:00:00Z",
		TotalRequests: 100,
		UniqueIPs:     20,
		AvgDurationMs: &avg,
		ErrorRate:     0.1,
		Series:        []TraefikBucket{{T: "2026-05-07T10:00:00Z", Total: 5, C2xx: 4, C5xx: 1}},
		StatusCodes:   []NameValue{{Name: "200", Value: 80}},
		TopIPs:        []IPStat{{IP: "1.2.3.4", Count: 9, Country: "US"}},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out TraefikDashboard
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.TotalRequests != in.TotalRequests || out.Format != "json" {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
	if out.AvgDurationMs == nil || *out.AvgDurationMs != avg {
		t.Fatalf("avg duration round-trip lost: %+v", out.AvgDurationMs)
	}
}

func TestTraefikDashboard_NilAvgDurationOmitted(t *testing.T) {
	d := TraefikDashboard{Range: Range5m, Format: "clf"}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// avg_duration_ms is *float64 with no omitempty (intentionally null in CLF mode).
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	v, ok := raw["avg_duration_ms"]
	if !ok || v != nil {
		t.Fatalf("expected explicit null for avg_duration_ms in CLF mode, got %v ok=%v", v, ok)
	}
}

func TestCrowdSecDashboard_JSONRoundTrip(t *testing.T) {
	in := CrowdSecDashboard{
		Range:        Range24h,
		TotalEvents:  10,
		Decisions:    3,
		Alerts:       2,
		ParserErrors: 1,
		Series:       []CrowdSecBucket{{T: "2026-05-07T10:00:00Z", Alerts: 2, Decisions: 3}},
		TopScenarios: []NameValue{{Name: "crowdsecurity/http-probing", Value: 4}},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out CrowdSecDashboard
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Decisions != 3 || len(out.TopScenarios) != 1 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestRange_KnownValues(t *testing.T) {
	for _, r := range []DashboardRange{Range5m, Range1h, Range6h, Range24h} {
		if r == "" {
			t.Fatalf("range constant must not be empty")
		}
	}
}
