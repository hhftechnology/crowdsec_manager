package history

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crowdsec-manager/internal/models"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "history-test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		if strings.Contains(err.Error(), "go-sqlite3 requires cgo") {
			t.Skip("sqlite3 cgo driver unavailable in this environment")
		}
		t.Fatalf("NewStore failed: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

func TestNormalizeRetentionDays(t *testing.T) {
	if got := NormalizeRetentionDays(0); got != 1 {
		t.Fatalf("expected min=1, got %d", got)
	}
	if got := NormalizeRetentionDays(366); got != 365 {
		t.Fatalf("expected max=365, got %d", got)
	}
	if got := NormalizeRetentionDays(30); got != 30 {
		t.Fatalf("expected unchanged, got %d", got)
	}
}

func TestDecisionSnapshotUpsertAndMarkStale(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	decision := models.Decision{
		ID:        42,
		AlertID:   100,
		Origin:    "crowdsec",
		Type:      "ban",
		Scope:     "Ip",
		Value:     "1.2.3.4",
		Duration:  "4h",
		Scenario:  "crowdsecurity/ssh-bf",
		CreatedAt: now.Add(-2 * time.Hour).Format(time.RFC3339),
	}

	if err := store.UpsertDecisionSnapshots(ctx, []UpsertDecisionInput{
		{Decision: decision, SnapshotAt: now},
	}); err != nil {
		t.Fatalf("UpsertDecisionSnapshots failed: %v", err)
	}

	records, total, err := store.ListDecisionHistory(ctx, models.DecisionHistoryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListDecisionHistory failed: %v", err)
	}
	if total != 1 || len(records) != 1 {
		t.Fatalf("expected 1 record total=%d len=%d", total, len(records))
	}
	if records[0].IsStale {
		t.Fatalf("expected fresh record")
	}

	later := now.Add(5 * time.Minute)
	if err := store.MarkMissingDecisionSnapshotsStale(ctx, later); err != nil {
		t.Fatalf("MarkMissingDecisionSnapshotsStale failed: %v", err)
	}

	records, _, err = store.ListDecisionHistory(ctx, models.DecisionHistoryFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListDecisionHistory after stale failed: %v", err)
	}
	if !records[0].IsStale {
		t.Fatalf("expected stale record")
	}
}

func TestRepeatedOffenderSuppression(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	offender := models.RepeatedOffender{
		Value:      "5.6.7.8",
		Scope:      "Ip",
		HitCount:   4,
		WindowDays: 30,
	}

	firstNotify, err := store.RecordRepeatedOffenderEvent(ctx, offender, now, 24*time.Hour)
	if err != nil {
		t.Fatalf("RecordRepeatedOffenderEvent first failed: %v", err)
	}
	if !firstNotify {
		t.Fatalf("expected first notification to be true")
	}

	secondNotify, err := store.RecordRepeatedOffenderEvent(ctx, offender, now.Add(30*time.Minute), 24*time.Hour)
	if err != nil {
		t.Fatalf("RecordRepeatedOffenderEvent second failed: %v", err)
	}
	if secondNotify {
		t.Fatalf("expected second notification to be suppressed")
	}
}

func TestParseDecisionsOutputNestedAndFlat(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	input := `[
		{"id":11,"created_at":"` + now + `","decisions":[{"id":1,"origin":"crowdsec","type":"ban","scope":"Ip","value":"1.1.1.1","duration":"4h","scenario":"a/b"}]},
		{"id":2,"origin":"cscli","type":"ban","scope":"Ip","value":"2.2.2.2","duration":"1h","scenario":"c/d","created_at":"` + now + `"}
	]`

	decisions, err := parseDecisionsOutput(input)
	if err != nil {
		t.Fatalf("parseDecisionsOutput failed: %v", err)
	}
	if len(decisions) != 2 {
		t.Fatalf("expected 2 decisions, got %d", len(decisions))
	}
	if decisions[0].AlertID != 11 {
		t.Fatalf("expected nested alert id to be set")
	}
	if decisions[1].Value != "2.2.2.2" {
		t.Fatalf("expected flat decision value")
	}
}
