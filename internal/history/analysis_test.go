package history

import (
	"context"
	"testing"
	"time"

	"crowdsec-manager/internal/models"
)

func TestDecisionHistoryAnalysisEmptyStoreNotReady(t *testing.T) {
	store := newTestStore(t)

	result, err := store.GetDecisionHistoryAnalysis(context.Background(), models.DecisionHistoryFilter{})
	if err != nil {
		t.Fatalf("GetDecisionHistoryAnalysis failed: %v", err)
	}
	if result.Ready {
		t.Fatalf("empty history should not be ready")
	}
	if result.Count != 0 || len(result.OverTime) != 0 || len(result.DecisionTypes) != 0 || len(result.TopIPs) != 0 {
		t.Fatalf("empty history returned data: %+v", result)
	}
}

func TestDecisionHistoryAnalysisAggregatesAndSorts(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	snapshotAt := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	decisions := []models.Decision{
		{ID: 1, AlertID: 10, Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: "2.2.2.2", Scenario: "crowdsecurity/http-probing", CreatedAt: "2026-05-04T10:00:00Z"},
		{ID: 2, AlertID: 11, Origin: "crowdsec", Type: "captcha", Scope: "Ip", Value: "1.1.1.1", Scenario: "crowdsecurity/ssh-bf", CreatedAt: "2026-05-05T10:00:00Z"},
		{ID: 3, AlertID: 12, Origin: "cscli", Type: "ban", Scope: "Ip", Value: "1.1.1.1", Scenario: "crowdsecurity/ssh-bf", CreatedAt: "2026-05-06T10:00:00Z"},
		{ID: 4, AlertID: 13, Origin: "crowdsec", Type: "ban", Scope: "Range", Value: "10.0.0.0/24", Scenario: "crowdsecurity/http-probing", CreatedAt: "2026-05-06T11:00:00Z"},
	}
	inputs := make([]UpsertDecisionInput, 0, len(decisions))
	for _, decision := range decisions {
		inputs = append(inputs, UpsertDecisionInput{Decision: decision, SnapshotAt: snapshotAt})
	}
	if err := store.UpsertDecisionSnapshots(ctx, inputs); err != nil {
		t.Fatalf("UpsertDecisionSnapshots failed: %v", err)
	}

	result, err := store.GetDecisionHistoryAnalysis(ctx, models.DecisionHistoryFilter{})
	if err != nil {
		t.Fatalf("GetDecisionHistoryAnalysis failed: %v", err)
	}
	if !result.Ready {
		t.Fatalf("history with rows should be ready")
	}
	if result.LatestSnapshotAt == nil || *result.LatestSnapshotAt == "" {
		t.Fatalf("expected latest snapshot timestamp")
	}
	if result.Count != 4 {
		t.Fatalf("count = %d, want 4", result.Count)
	}
	wantTimeline := []string{"2026-05-04T00:00:00Z", "2026-05-05T00:00:00Z", "2026-05-06T00:00:00Z"}
	if len(result.OverTime) != len(wantTimeline) {
		t.Fatalf("timeline len = %d, want %d: %+v", len(result.OverTime), len(wantTimeline), result.OverTime)
	}
	for i, want := range wantTimeline {
		if result.OverTime[i].Timestamp != want {
			t.Fatalf("timeline[%d] = %q, want %q", i, result.OverTime[i].Timestamp, want)
		}
	}
	if got := result.DecisionTypes[0]; got.Name != "ban" || got.Value != 3 {
		t.Fatalf("top decision type = %+v, want ban=3", got)
	}
	if got := result.TopIPs[0]; got.Name != "1.1.1.1" || got.Value != 2 {
		t.Fatalf("top IP = %+v, want 1.1.1.1=2", got)
	}
	for _, item := range result.TopIPs {
		if item.Name == "10.0.0.0/24" {
			t.Fatalf("range values should not appear in top IPs: %+v", result.TopIPs)
		}
	}
}

func TestDecisionHistoryAnalysisFilters(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	inputs := []UpsertDecisionInput{
		{Decision: models.Decision{ID: 1, AlertID: 1, Origin: "crowdsec", Type: "ban", Scope: "Ip", Value: "1.1.1.1", Scenario: "crowdsecurity/ssh-bf", CreatedAt: now.Add(-2 * time.Hour).Format(time.RFC3339)}, SnapshotAt: now},
		{Decision: models.Decision{ID: 2, AlertID: 2, Origin: "crowdsec", Type: "captcha", Scope: "Ip", Value: "2.2.2.2", Scenario: "crowdsecurity/http-probing", CreatedAt: now.Add(-48 * time.Hour).Format(time.RFC3339)}, SnapshotAt: now},
	}
	if err := store.UpsertDecisionSnapshots(ctx, inputs); err != nil {
		t.Fatalf("UpsertDecisionSnapshots failed: %v", err)
	}

	result, err := store.GetDecisionHistoryAnalysis(ctx, models.DecisionHistoryFilter{Since: "4h", Type: "ban"})
	if err != nil {
		t.Fatalf("GetDecisionHistoryAnalysis failed: %v", err)
	}
	if !result.Ready {
		t.Fatalf("history should remain ready when filters match rows")
	}
	if result.Count != 1 {
		t.Fatalf("filtered count = %d, want 1", result.Count)
	}
	if got := result.TopIPs[0]; got.Name != "1.1.1.1" || got.Value != 1 {
		t.Fatalf("filtered top IP = %+v, want 1.1.1.1=1", got)
	}

	zero, err := store.GetDecisionHistoryAnalysis(ctx, models.DecisionHistoryFilter{Type: "throttle"})
	if err != nil {
		t.Fatalf("GetDecisionHistoryAnalysis zero failed: %v", err)
	}
	if !zero.Ready || zero.Count != 0 {
		t.Fatalf("filtered zero should still be ready with count=0: %+v", zero)
	}
}
