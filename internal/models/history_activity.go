package models

// HistoryActivityResponse provides UTC bucketed activity counts for dashboards.
type HistoryActivityResponse struct {
	Window           string                  `json:"window"`
	Bucket           string                  `json:"bucket"`
	GeneratedAt      string                  `json:"generated_at"`
	LatestSnapshotAt *string                 `json:"latest_snapshot_at"`
	Buckets          []HistoryActivityBucket `json:"buckets"`
}

// HistoryActivityBucket is a single UTC activity bucket.
type HistoryActivityBucket struct {
	Timestamp string `json:"ts"`
	Alerts    int    `json:"alerts"`
	Decisions int    `json:"decisions"`
}
