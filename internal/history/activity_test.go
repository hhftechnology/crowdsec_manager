package history

import (
	"context"
	"errors"
	"testing"
	"time"

	"crowdsec-manager/internal/models"
)

func TestGetActivityBuckets_EmptyDB(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	endAt := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)

	result, err := store.GetActivityBuckets(ctx, GetActivityBucketsInput{
		Window: 24 * time.Hour,
		Bucket: ActivityBucketHour,
		EndAt:  endAt,
	})
	if err != nil {
		t.Fatalf("GetActivityBuckets on empty DB failed: %v", err)
	}
	if len(result.Buckets) != 24 {
		t.Fatalf("expected 24 zero-filled buckets, got %d", len(result.Buckets))
	}
	for i, b := range result.Buckets {
		if b.Alerts != 0 || b.Decisions != 0 {
			t.Fatalf("bucket %d should be zero-filled, got alerts=%d decisions=%d", i, b.Alerts, b.Decisions)
		}
	}
	if result.LatestSnapshotAt != nil {
		t.Fatalf("expected nil LatestSnapshotAt for empty DB, got %v", result.LatestSnapshotAt)
	}
}

func TestGetActivityBuckets_HourlyGapFillSortedAndMixedCounts(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	endAt := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)

	alerts := []AlertSnapshot{
		{
			ID:          1,
			Scenario:    "crowdsecurity/http-probing",
			Scope:       "Ip",
			Value:       "1.1.1.1",
			Origin:      "crowdsec",
			Type:        "ban",
			EventsCount: 1,
			StartAt:     endAt.Add(-3 * time.Hour).Format(time.RFC3339),
		},
		{
			ID:          2,
			Scenario:    "crowdsecurity/ssh-bf",
			Scope:       "Ip",
			Value:       "2.2.2.2",
			Origin:      "crowdsec",
			Type:        "ban",
			EventsCount: 1,
			StartAt:     endAt.Add(-10 * time.Hour).Format(time.RFC3339),
		},
	}
	for _, alert := range alerts {
		if err := store.UpsertAlertSnapshots(ctx, []UpsertAlertInput{{Alert: alert, SnapshotAt: endAt}}); err != nil {
			t.Fatalf("UpsertAlertSnapshots failed: %v", err)
		}
	}

	decisions := []models.Decision{
		{
			ID:        1,
			Origin:    "crowdsec",
			Type:      "ban",
			Scope:     "Ip",
			Value:     "3.3.3.3",
			Duration:  "4h",
			Scenario:  "crowdsecurity/http-probing",
			CreatedAt: endAt.Add(-1 * time.Hour).Format(time.RFC3339),
		},
		{
			ID:        2,
			Origin:    "crowdsec",
			Type:      "ban",
			Scope:     "Ip",
			Value:     "4.4.4.4",
			Duration:  "4h",
			Scenario:  "crowdsecurity/ssh-bf",
			CreatedAt: endAt.Add(-5 * time.Hour).Format(time.RFC3339),
		},
	}
	for _, decision := range decisions {
		if err := store.UpsertDecisionSnapshots(ctx, []UpsertDecisionInput{{Decision: decision, SnapshotAt: endAt}}); err != nil {
			t.Fatalf("UpsertDecisionSnapshots failed: %v", err)
		}
	}

	result, err := store.GetActivityBuckets(ctx, GetActivityBucketsInput{
		Window: 24 * time.Hour,
		Bucket: ActivityBucketHour,
		EndAt:  endAt,
	})
	if err != nil {
		t.Fatalf("GetActivityBuckets failed: %v", err)
	}
	if len(result.Buckets) != 24 {
		t.Fatalf("expected 24 buckets, got %d", len(result.Buckets))
	}
	assertActivityBucketsSorted(t, result.Buckets)

	wantAlerts := map[string]int{
		endAt.Add(-3 * time.Hour).Format(time.RFC3339):  1,
		endAt.Add(-10 * time.Hour).Format(time.RFC3339): 1,
	}
	wantDecisions := map[string]int{
		endAt.Add(-1 * time.Hour).Format(time.RFC3339): 1,
		endAt.Add(-5 * time.Hour).Format(time.RFC3339): 1,
	}
	for _, bucket := range result.Buckets {
		if got, want := bucket.Alerts, wantAlerts[bucket.Timestamp]; got != want {
			t.Fatalf("alerts mismatch for %s: got %d want %d", bucket.Timestamp, got, want)
		}
		if got, want := bucket.Decisions, wantDecisions[bucket.Timestamp]; got != want {
			t.Fatalf("decisions mismatch for %s: got %d want %d", bucket.Timestamp, got, want)
		}
	}

	if result.LatestSnapshotAt == nil {
		t.Fatalf("expected latest snapshot timestamp")
	}
	expectedLatest := endAt.Add(-1 * time.Hour)
	if !result.LatestSnapshotAt.Equal(expectedLatest) {
		t.Fatalf("latest snapshot mismatch: got %v want %v", result.LatestSnapshotAt, expectedLatest)
	}
}

func TestGetActivityBuckets_DailyGapFillSortedAndMixedCounts(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	endAt := time.Date(2026, 4, 24, 0, 0, 0, 0, time.UTC)

	if err := store.UpsertAlertSnapshots(ctx, []UpsertAlertInput{
		{
			Alert: AlertSnapshot{
				ID:          1,
				Scenario:    "crowdsecurity/http-probing",
				Scope:       "Ip",
				Value:       "1.1.1.1",
				Origin:      "crowdsec",
				Type:        "ban",
				EventsCount: 1,
				StartAt:     endAt.AddDate(0, 0, -2).Add(3 * time.Hour).Format(time.RFC3339),
			},
			SnapshotAt: endAt,
		},
	}); err != nil {
		t.Fatalf("UpsertAlertSnapshots failed: %v", err)
	}

	if err := store.UpsertDecisionSnapshots(ctx, []UpsertDecisionInput{
		{
			Decision: models.Decision{
				ID:        1,
				Origin:    "crowdsec",
				Type:      "ban",
				Scope:     "Ip",
				Value:     "2.2.2.2",
				Duration:  "4h",
				Scenario:  "crowdsecurity/ssh-bf",
				CreatedAt: endAt.AddDate(0, 0, -5).Add(8 * time.Hour).Format(time.RFC3339),
			},
			SnapshotAt: endAt,
		},
	}); err != nil {
		t.Fatalf("UpsertDecisionSnapshots failed: %v", err)
	}

	result, err := store.GetActivityBuckets(ctx, GetActivityBucketsInput{
		Window: 7 * 24 * time.Hour,
		Bucket: ActivityBucketDay,
		EndAt:  endAt,
	})
	if err != nil {
		t.Fatalf("GetActivityBuckets failed: %v", err)
	}
	if len(result.Buckets) != 7 {
		t.Fatalf("expected 7 buckets, got %d", len(result.Buckets))
	}
	assertActivityBucketsSorted(t, result.Buckets)

	alertTS := endAt.AddDate(0, 0, -2).Format(time.RFC3339)
	decisionTS := endAt.AddDate(0, 0, -5).Format(time.RFC3339)
	for _, bucket := range result.Buckets {
		wantAlerts := 0
		if bucket.Timestamp == alertTS {
			wantAlerts = 1
		}
		wantDecisions := 0
		if bucket.Timestamp == decisionTS {
			wantDecisions = 1
		}
		if bucket.Alerts != wantAlerts || bucket.Decisions != wantDecisions {
			t.Fatalf("bucket %s mismatch: got alerts=%d decisions=%d want alerts=%d decisions=%d", bucket.Timestamp, bucket.Alerts, bucket.Decisions, wantAlerts, wantDecisions)
		}
	}
}

func TestGetActivityBuckets_DailyIncludesCurrentDayFinalBucket(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	today := time.Date(2026, 4, 24, 0, 0, 0, 0, time.UTC)
	endAt := today.Add(24 * time.Hour)

	if err := store.UpsertAlertSnapshots(ctx, []UpsertAlertInput{
		{
			Alert: AlertSnapshot{
				ID:          1,
				Scenario:    "crowdsecurity/http-probing",
				Scope:       "Ip",
				Value:       "1.1.1.1",
				Origin:      "crowdsec",
				Type:        "ban",
				EventsCount: 1,
				StartAt:     today.Add(15 * time.Hour).Format(time.RFC3339),
			},
			SnapshotAt: today.Add(16 * time.Hour),
		},
	}); err != nil {
		t.Fatalf("UpsertAlertSnapshots failed: %v", err)
	}

	result, err := store.GetActivityBuckets(ctx, GetActivityBucketsInput{
		Window: 7 * 24 * time.Hour,
		Bucket: ActivityBucketDay,
		EndAt:  endAt,
	})
	if err != nil {
		t.Fatalf("GetActivityBuckets failed: %v", err)
	}
	if len(result.Buckets) != 7 {
		t.Fatalf("expected 7 buckets, got %d", len(result.Buckets))
	}

	last := result.Buckets[len(result.Buckets)-1]
	if last.Timestamp != today.Format(time.RFC3339) {
		t.Fatalf("final bucket timestamp mismatch: got %s want %s", last.Timestamp, today.Format(time.RFC3339))
	}
	if last.Alerts != 1 {
		t.Fatalf("expected current-day alert in final bucket, got %d", last.Alerts)
	}
}

func TestGetActivityBuckets_LatestSnapshotAt_AlertsOnly(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	alertTime := now.Add(-30 * time.Minute)

	alert := AlertSnapshot{
		ID:          1,
		Scenario:    "crowdsecurity/http-probing",
		Scope:       "Ip",
		Value:       "1.1.1.1",
		Origin:      "crowdsec",
		Type:        "ban",
		EventsCount: 1,
		StartAt:     alertTime.Format(time.RFC3339),
	}
	if err := store.UpsertAlertSnapshots(ctx, []UpsertAlertInput{
		{Alert: alert, SnapshotAt: now},
	}); err != nil {
		t.Fatalf("UpsertAlertSnapshots failed: %v", err)
	}

	result, err := store.GetActivityBuckets(ctx, GetActivityBucketsInput{
		Window: 24 * time.Hour,
		Bucket: ActivityBucketHour,
		EndAt:  now,
	})
	if err != nil {
		t.Fatalf("GetActivityBuckets failed: %v", err)
	}
	if result.LatestSnapshotAt == nil {
		t.Fatalf("expected non-nil LatestSnapshotAt")
	}
	expected := alertTime.UTC().Truncate(time.Second)
	got := result.LatestSnapshotAt.UTC().Truncate(time.Second)
	if !got.Equal(expected) {
		t.Fatalf("expected LatestSnapshotAt %v, got %v", expected, got)
	}
}

func TestGetActivityBuckets_LatestSnapshotAt_DecisionsOnly(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	decisionTime := now.Add(-45 * time.Minute)

	decision := models.Decision{
		ID:        1,
		Origin:    "crowdsec",
		Type:      "ban",
		Scope:     "Ip",
		Value:     "2.2.2.2",
		Duration:  "4h",
		Scenario:  "crowdsecurity/ssh-bf",
		CreatedAt: decisionTime.Format(time.RFC3339),
	}
	if err := store.UpsertDecisionSnapshots(ctx, []UpsertDecisionInput{
		{Decision: decision, SnapshotAt: now},
	}); err != nil {
		t.Fatalf("UpsertDecisionSnapshots failed: %v", err)
	}

	result, err := store.GetActivityBuckets(ctx, GetActivityBucketsInput{
		Window: 24 * time.Hour,
		Bucket: ActivityBucketHour,
		EndAt:  now,
	})
	if err != nil {
		t.Fatalf("GetActivityBuckets failed: %v", err)
	}
	if result.LatestSnapshotAt == nil {
		t.Fatalf("expected non-nil LatestSnapshotAt")
	}
	expected := decisionTime.UTC().Truncate(time.Second)
	got := result.LatestSnapshotAt.UTC().Truncate(time.Second)
	if !got.Equal(expected) {
		t.Fatalf("expected LatestSnapshotAt %v, got %v", expected, got)
	}
}

func TestGetActivityBuckets_LatestSnapshotAt_Both(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC)
	alertTime := now.Add(-20 * time.Minute)
	decisionTime := now.Add(-10 * time.Minute) // newer — should win

	alert := AlertSnapshot{
		ID:          1,
		Scenario:    "crowdsecurity/http-probing",
		Scope:       "Ip",
		Value:       "1.1.1.1",
		Origin:      "crowdsec",
		Type:        "ban",
		EventsCount: 1,
		StartAt:     alertTime.Format(time.RFC3339),
	}
	decision := models.Decision{
		ID:        1,
		Origin:    "crowdsec",
		Type:      "ban",
		Scope:     "Ip",
		Value:     "2.2.2.2",
		Duration:  "4h",
		Scenario:  "crowdsecurity/ssh-bf",
		CreatedAt: decisionTime.Format(time.RFC3339),
	}
	if err := store.UpsertAlertSnapshots(ctx, []UpsertAlertInput{
		{Alert: alert, SnapshotAt: now},
	}); err != nil {
		t.Fatalf("UpsertAlertSnapshots failed: %v", err)
	}
	if err := store.UpsertDecisionSnapshots(ctx, []UpsertDecisionInput{
		{Decision: decision, SnapshotAt: now},
	}); err != nil {
		t.Fatalf("UpsertDecisionSnapshots failed: %v", err)
	}

	result, err := store.GetActivityBuckets(ctx, GetActivityBucketsInput{
		Window: 24 * time.Hour,
		Bucket: ActivityBucketHour,
		EndAt:  now,
	})
	if err != nil {
		t.Fatalf("GetActivityBuckets failed: %v", err)
	}
	if result.LatestSnapshotAt == nil {
		t.Fatalf("expected non-nil LatestSnapshotAt")
	}
	expected := decisionTime.UTC().Truncate(time.Second)
	got := result.LatestSnapshotAt.UTC().Truncate(time.Second)
	if !got.Equal(expected) {
		t.Fatalf("expected LatestSnapshotAt %v (newer decision), got %v", expected, got)
	}
}

func TestGetActivityBuckets_NilStore(t *testing.T) {
	var store *Store
	ctx := context.Background()
	_, err := store.GetActivityBuckets(ctx, GetActivityBucketsInput{
		Window: 24 * time.Hour,
		Bucket: ActivityBucketHour,
		EndAt:  time.Now(),
	})
	if !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("expected ErrStoreUnavailable, got %v", err)
	}
}

func TestGetActivityBuckets_ClosedStore(t *testing.T) {
	store := newTestStore(t)
	if err := store.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	_, err := store.GetActivityBuckets(context.Background(), GetActivityBucketsInput{
		Window: 24 * time.Hour,
		Bucket: ActivityBucketHour,
		EndAt:  time.Date(2026, 4, 23, 12, 0, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatalf("expected error for closed store")
	}
}

func assertActivityBucketsSorted(t *testing.T, buckets []models.HistoryActivityBucket) {
	t.Helper()
	for i, bucket := range buckets {
		if _, err := time.Parse(time.RFC3339, bucket.Timestamp); err != nil {
			t.Fatalf("bucket %d timestamp is not RFC3339: %v", i, err)
		}
		if i == 0 {
			continue
		}
		if buckets[i-1].Timestamp >= bucket.Timestamp {
			t.Fatalf("buckets not sorted at %d: %q >= %q", i, buckets[i-1].Timestamp, bucket.Timestamp)
		}
	}
}
