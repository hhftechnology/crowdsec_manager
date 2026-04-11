package handlers

import (
	"fmt"
	"testing"
	"time"

	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
)

func init() {
	logger.Init("info", "")
}

// ---- parseBouncersJSON tests ----

func TestParseBouncersJSON_EmptyArray(t *testing.T) {
	// Only "[]" is a valid JSON array. "null" and "" contain no JSON structure
	// characters and callers (checkBouncersHealth) guard against those strings
	// before calling parseBouncersJSON.
	bouncers, err := parseBouncersJSON("[]", false)
	if err != nil {
		t.Fatalf("unexpected error for '[]': %v", err)
	}
	if len(bouncers) != 0 {
		t.Errorf("expected 0 bouncers, got %d", len(bouncers))
	}
}

func TestParseBouncersJSON_NullAndEmptyReturnError(t *testing.T) {
	// "null" and "" reach parseCLIJSONToBytes which cannot find any JSON delimiter.
	// Callers of parseBouncersJSON guard against these values in production code.
	for _, input := range []string{"null", ""} {
		t.Run(fmt.Sprintf("input=%q", input), func(t *testing.T) {
			_, err := parseBouncersJSON(input, false)
			if err == nil {
				t.Errorf("expected error for %q, got nil", input)
			}
		})
	}
}

func TestParseBouncersJSON_SingleBouncer(t *testing.T) {
	input := `[{"name":"traefik-bouncer","ip_address":"172.17.0.2","last_pull":"2024-06-01T12:00:00Z","created_at":"2024-01-01T00:00:00Z","updated_at":"2024-06-01T12:00:00Z","type":"traefik","version":"v1.0.0"}]`

	bouncers, err := parseBouncersJSON(input, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bouncers) != 1 {
		t.Fatalf("expected 1 bouncer, got %d", len(bouncers))
	}

	b := bouncers[0]
	if b.Name != "traefik-bouncer" {
		t.Errorf("Name: got %q, want %q", b.Name, "traefik-bouncer")
	}
	if b.IPAddress != "172.17.0.2" {
		t.Errorf("IPAddress: got %q, want %q", b.IPAddress, "172.17.0.2")
	}
	if b.Type != "traefik" {
		t.Errorf("Type: got %q, want %q", b.Type, "traefik")
	}
	if b.Version != "v1.0.0" {
		t.Errorf("Version: got %q, want %q", b.Version, "v1.0.0")
	}
	if !b.Valid {
		t.Error("Valid should be true")
	}
}

func TestParseBouncersJSON_ComputeStatusConnected(t *testing.T) {
	recentTime := time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339)
	input := fmt.Sprintf(`[{"name":"active-bouncer","ip_address":"10.0.0.1","last_pull":%q,"created_at":"2024-01-01T00:00:00Z","type":"traefik"}]`, recentTime)

	bouncers, err := parseBouncersJSON(input, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bouncers) != 1 {
		t.Fatalf("expected 1 bouncer, got %d", len(bouncers))
	}
	if bouncers[0].Status != "connected" {
		t.Errorf("Status: got %q, want %q", bouncers[0].Status, "connected")
	}
}

func TestParseBouncersJSON_ComputeStatusStale(t *testing.T) {
	staleTime := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	input := fmt.Sprintf(`[{"name":"stale-bouncer","ip_address":"10.0.0.2","last_pull":%q,"created_at":"2024-01-01T00:00:00Z","type":"nginx"}]`, staleTime)

	bouncers, err := parseBouncersJSON(input, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bouncers) != 1 {
		t.Fatalf("expected 1 bouncer, got %d", len(bouncers))
	}
	if bouncers[0].Status != "stale" {
		t.Errorf("Status: got %q, want %q", bouncers[0].Status, "stale")
	}
}

func TestParseBouncersJSON_ComputeStatusRegistered(t *testing.T) {
	// bouncer with no last_pull — zero LastActivity → "registered"
	input := `[{"name":"new-bouncer","ip_address":"10.0.0.3","created_at":"2024-01-01T00:00:00Z","type":"custom"}]`

	bouncers, err := parseBouncersJSON(input, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bouncers) != 1 {
		t.Fatalf("expected 1 bouncer, got %d", len(bouncers))
	}
	if bouncers[0].Status != "registered" {
		t.Errorf("Status: got %q, want %q", bouncers[0].Status, "registered")
	}
}

func TestParseBouncersJSON_NoStatusWhenComputeStatusFalse(t *testing.T) {
	recentTime := time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339)
	input := fmt.Sprintf(`[{"name":"b","ip_address":"1.2.3.4","last_pull":%q,"created_at":"2024-01-01T00:00:00Z"}]`, recentTime)

	bouncers, err := parseBouncersJSON(input, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bouncers) != 1 {
		t.Fatalf("expected 1 bouncer, got %d", len(bouncers))
	}
	// When computeStatus is false, Status field should remain empty (not set)
	if bouncers[0].Status != "" {
		t.Errorf("Status should be empty when computeStatus=false, got %q", bouncers[0].Status)
	}
}

func TestParseBouncersJSON_MultipleBouncer(t *testing.T) {
	input := `[
		{"name":"b1","ip_address":"1.1.1.1","created_at":"2024-01-01T00:00:00Z","type":"traefik"},
		{"name":"b2","ip_address":"2.2.2.2","created_at":"2024-01-01T00:00:00Z","type":"nginx"},
		{"name":"b3","ip_address":"3.3.3.3","created_at":"2024-01-01T00:00:00Z","type":"custom"}
	]`

	bouncers, err := parseBouncersJSON(input, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(bouncers) != 3 {
		t.Fatalf("expected 3 bouncers, got %d", len(bouncers))
	}
	names := []string{"b1", "b2", "b3"}
	for i, b := range bouncers {
		if b.Name != names[i] {
			t.Errorf("bouncers[%d].Name: got %q, want %q", i, b.Name, names[i])
		}
	}
}

func TestParseBouncersJSON_InvalidJSON(t *testing.T) {
	_, err := parseBouncersJSON("not json at all", false)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// ---- Bouncer.LastActivity tests (model behaviour exercised via parseBouncersJSON) ----

func TestBouncerLastActivity_PrefersLastPull(t *testing.T) {
	b := models.Bouncer{
		LastPull:  time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC),
		CreatedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2024, 5, 1, 0, 0, 0, 0, time.UTC),
	}
	if got := b.LastActivity(); !got.Equal(b.LastPull) {
		t.Errorf("expected LastPull %v, got %v", b.LastPull, got)
	}
}

func TestBouncerLastActivity_FallsBackToUpdatedAt(t *testing.T) {
	b := models.Bouncer{
		CreatedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedAt: time.Date(2024, 1, 1, 0, 1, 0, 0, time.UTC), // 1 min after created — > 5s threshold
	}
	if got := b.LastActivity(); !got.Equal(b.UpdatedAt) {
		t.Errorf("expected UpdatedAt %v, got %v", b.UpdatedAt, got)
	}
}

func TestBouncerLastActivity_ZeroWhenNoData(t *testing.T) {
	b := models.Bouncer{}
	if got := b.LastActivity(); !got.IsZero() {
		t.Errorf("expected zero time, got %v", got)
	}
}