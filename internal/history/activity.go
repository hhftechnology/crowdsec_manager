package history

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"crowdsec-manager/internal/models"
)

// ErrStoreUnavailable indicates that the history store is not ready for queries.
var ErrStoreUnavailable = errors.New("history store unavailable")

// ActivityBucket is the supported aggregation granularity.
type ActivityBucket string

const (
	ActivityBucketHour ActivityBucket = "hour"
	ActivityBucketDay  ActivityBucket = "day"
)

// GetActivityBucketsInput configures dashboard activity aggregation.
type GetActivityBucketsInput struct {
	Window time.Duration
	Bucket ActivityBucket
	EndAt  time.Time
}

// ActivityBuckets is the gap-filled activity result from history storage.
type ActivityBuckets struct {
	Buckets          []models.HistoryActivityBucket
	LatestSnapshotAt *time.Time
}

func (s *Store) GetActivityBuckets(ctx context.Context, in GetActivityBucketsInput) (ActivityBuckets, error) {
	if s == nil || s.db == nil {
		return ActivityBuckets{}, ErrStoreUnavailable
	}

	endAt := in.EndAt.UTC()
	step := time.Hour
	if in.Bucket == ActivityBucketDay {
		step = 24 * time.Hour
	}
	startAt := endAt.Add(-in.Window)

	buckets := make([]models.HistoryActivityBucket, 0, int(in.Window/step))
	byTS := make(map[string]int, int(in.Window/step))
	for ts := startAt; ts.Before(endAt); ts = ts.Add(step) {
		key := ts.UTC().Format(time.RFC3339)
		byTS[key] = len(buckets)
		buckets = append(buckets, models.HistoryActivityBucket{Timestamp: key})
	}

	if err := s.loadActivityCounts(ctx, loadActivityCountsInput{
		Table:     "alert_history",
		Column:    "start_at",
		CountKind: "alerts",
		Bucket:    in.Bucket,
		StartAt:   startAt,
		EndAt:     endAt,
		Buckets:   buckets,
		Indexes:   byTS,
	}); err != nil {
		return ActivityBuckets{}, fmt.Errorf("load alert activity counts: %w", err)
	}
	if err := s.loadActivityCounts(ctx, loadActivityCountsInput{
		Table:     "decision_history",
		Column:    "created_at",
		CountKind: "decisions",
		Bucket:    in.Bucket,
		StartAt:   startAt,
		EndAt:     endAt,
		Buckets:   buckets,
		Indexes:   byTS,
	}); err != nil {
		return ActivityBuckets{}, fmt.Errorf("load decision activity counts: %w", err)
	}

	latest, err := s.latestActivitySnapshotAt(ctx)
	if err != nil {
		return ActivityBuckets{}, fmt.Errorf("load latest activity snapshot: %w", err)
	}

	return ActivityBuckets{Buckets: buckets, LatestSnapshotAt: latest}, nil
}

func (s *Service) GetActivityBuckets(ctx context.Context, in GetActivityBucketsInput) (ActivityBuckets, error) {
	if s == nil || s.store == nil {
		return ActivityBuckets{}, ErrStoreUnavailable
	}
	return s.store.GetActivityBuckets(ctx, in)
}

type loadActivityCountsInput struct {
	Table     string
	Column    string
	CountKind string
	Bucket    ActivityBucket
	StartAt   time.Time
	EndAt     time.Time
	Buckets   []models.HistoryActivityBucket
	Indexes   map[string]int
}

func (s *Store) loadActivityCounts(ctx context.Context, in loadActivityCountsInput) error {
	bucketExpr := "strftime('%Y-%m-%dT%H:00:00Z', datetime(" + in.Column + "))"
	if in.Bucket == ActivityBucketDay {
		bucketExpr = "strftime('%Y-%m-%dT00:00:00Z', datetime(" + in.Column + "))"
	}

	query := fmt.Sprintf(`
		SELECT %s AS bucket_start, COUNT(1)
		FROM %s
		WHERE datetime(%s) >= datetime(?) AND datetime(%s) < datetime(?)
		GROUP BY bucket_start
		ORDER BY bucket_start
	`, bucketExpr, in.Table, in.Column, in.Column)

	rows, err := s.db.QueryContext(ctx, query, in.StartAt.UTC().Format(time.RFC3339), in.EndAt.UTC().Format(time.RFC3339))
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var bucketStart string
		var count int
		if err := rows.Scan(&bucketStart, &count); err != nil {
			return err
		}
		idx, ok := in.Indexes[bucketStart]
		if !ok {
			continue
		}
		if in.CountKind == "alerts" {
			in.Buckets[idx].Alerts = count
		} else {
			in.Buckets[idx].Decisions = count
		}
	}
	return rows.Err()
}

func (s *Store) latestActivitySnapshotAt(ctx context.Context) (*time.Time, error) {
	var latest sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT MAX(ts)
		FROM (
			SELECT MAX(strftime('%Y-%m-%dT%H:%M:%SZ', datetime(start_at))) AS ts
			FROM alert_history
			WHERE datetime(start_at) IS NOT NULL
			UNION ALL
			SELECT MAX(strftime('%Y-%m-%dT%H:%M:%SZ', datetime(created_at))) AS ts
			FROM decision_history
			WHERE datetime(created_at) IS NOT NULL
		)
	`).Scan(&latest)
	if err != nil {
		return nil, err
	}
	if !latest.Valid || latest.String == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, latest.String)
	if err != nil {
		return nil, fmt.Errorf("parse latest activity timestamp %q: %w", latest.String, err)
	}
	utc := parsed.UTC()
	return &utc, nil
}
