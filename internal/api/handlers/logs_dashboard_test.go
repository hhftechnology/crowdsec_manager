package handlers

import (
	"testing"
	"time"

	"crowdsec-manager/internal/models"
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
