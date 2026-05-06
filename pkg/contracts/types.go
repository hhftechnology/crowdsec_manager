package contracts

// AddDecisionRequest is the payload for adding a CrowdSec decision.
type AddDecisionRequest struct {
	IP       string `json:"ip,omitempty"`
	Range    string `json:"range,omitempty"`
	Duration string `json:"duration,omitempty"`
	Type     string `json:"type,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Value    string `json:"value,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Origin   string `json:"origin,omitempty"`
}

// DeleteDecisionRequest is the query/body shape for deleting decisions.
type DeleteDecisionRequest struct {
	ID       string `json:"id,omitempty"`
	IP       string `json:"ip,omitempty"`
	Range    string `json:"range,omitempty"`
	Type     string `json:"type,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Value    string `json:"value,omitempty"`
	Scenario string `json:"scenario,omitempty"`
	Origin   string `json:"origin,omitempty"`
}

// Decision is an active CrowdSec decision.
type Decision struct {
	ID        int64  `json:"id"`
	AlertID   int64  `json:"alert_id"`
	Origin    string `json:"origin"`
	Source    string `json:"source,omitempty"`
	Type      string `json:"type"`
	Scope     string `json:"scope"`
	Value     string `json:"value"`
	Duration  string `json:"duration"`
	Scenario  string `json:"scenario"`
	Reason    string `json:"reason,omitempty"`
	CreatedAt string `json:"created_at"`
	Until     string `json:"until,omitempty"`
}

// DecisionsResponse is returned by decision list endpoints.
type DecisionsResponse struct {
	Decisions []Decision `json:"decisions"`
	Count     int        `json:"count"`
	Total     int        `json:"total,omitempty"`
	Limit     int        `json:"limit,omitempty"`
	Offset    int        `json:"offset,omitempty"`
}

// BulkDeleteDecisionsRequest is the payload for bulk decision deletion.
type BulkDeleteDecisionsRequest struct {
	IDs []int64 `json:"ids"`
}

// BulkDeleteFailure reports one failed decision deletion.
type BulkDeleteFailure struct {
	ID    int64  `json:"id"`
	Error string `json:"error"`
}

// BulkDeleteDecisionsResponse reports bulk delete outcomes.
type BulkDeleteDecisionsResponse struct {
	SuccessCount int                 `json:"success_count"`
	FailureCount int                 `json:"failure_count"`
	Deleted      []int64             `json:"deleted"`
	Failed       []BulkDeleteFailure `json:"failed"`
}

// AlertSource is the normalized source metadata for an alert.
type AlertSource struct {
	CountryCode string  `json:"cn,omitempty"`
	ASName      string  `json:"as_name,omitempty"`
	ASNumber    string  `json:"as_number,omitempty"`
	IP          string  `json:"ip,omitempty"`
	Range       string  `json:"range,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	Scope       string  `json:"scope,omitempty"`
	Value       string  `json:"value,omitempty"`
}

// AlertEvent is a normalized CrowdSec alert event.
type AlertEvent struct {
	Timestamp string              `json:"timestamp"`
	Meta      []map[string]string `json:"meta,omitempty"`
}

// CrowdSecAlert is a CrowdSec alert with optional decisions and source data.
type CrowdSecAlert struct {
	ID          int64        `json:"id"`
	Scenario    string       `json:"scenario"`
	Scope       string       `json:"scope"`
	Value       string       `json:"value"`
	Origin      string       `json:"origin"`
	Type        string       `json:"type,omitempty"`
	Message     string       `json:"message,omitempty"`
	EventsCount int          `json:"events_count,omitempty"`
	StartAt     string       `json:"start_at"`
	StopAt      string       `json:"stop_at,omitempty"`
	Capacity    int          `json:"capacity,omitempty"`
	Leakspeed   string       `json:"leakspeed,omitempty"`
	Simulated   bool         `json:"simulated,omitempty"`
	Decisions   []Decision   `json:"decisions,omitempty"`
	Source      *AlertSource `json:"source,omitempty"`
	Events      []AlertEvent `json:"events,omitempty"`
}

// AlertsResponse is returned by alert list endpoints.
type AlertsResponse struct {
	Alerts []CrowdSecAlert `json:"alerts"`
	Count  int             `json:"count"`
}

// DecisionFilters are supported decision analysis filters.
type DecisionFilters struct {
	Since      string `json:"since,omitempty"`
	Until      string `json:"until,omitempty"`
	Type       string `json:"type,omitempty"`
	Scope      string `json:"scope,omitempty"`
	Origin     string `json:"origin,omitempty"`
	Value      string `json:"value,omitempty"`
	Scenario   string `json:"scenario,omitempty"`
	IP         string `json:"ip,omitempty"`
	Range      string `json:"range,omitempty"`
	IncludeAll bool   `json:"includeAll,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
}

// AlertFilters are supported alert analysis filters.
type AlertFilters struct {
	Since      string `json:"since,omitempty"`
	Until      string `json:"until,omitempty"`
	IP         string `json:"ip,omitempty"`
	Range      string `json:"range,omitempty"`
	Scope      string `json:"scope,omitempty"`
	Value      string `json:"value,omitempty"`
	Scenario   string `json:"scenario,omitempty"`
	Type       string `json:"type,omitempty"`
	Origin     string `json:"origin,omitempty"`
	IncludeAll bool   `json:"includeAll,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
}

// DecisionHistoryRecord is a persisted decision snapshot.
type DecisionHistoryRecord struct {
	ID             int64  `json:"id"`
	DedupeKey      string `json:"dedupe_key"`
	DecisionID     int64  `json:"decision_id"`
	AlertID        int64  `json:"alert_id"`
	Origin         string `json:"origin"`
	Type           string `json:"type"`
	Scope          string `json:"scope"`
	Value          string `json:"value"`
	Duration       string `json:"duration"`
	Scenario       string `json:"scenario"`
	CreatedAt      string `json:"created_at"`
	Until          string `json:"until,omitempty"`
	IsStale        bool   `json:"is_stale"`
	FirstSeenAt    string `json:"first_seen_at"`
	LastSeenAt     string `json:"last_seen_at"`
	StaleAt        string `json:"stale_at,omitempty"`
	LastSnapshotAt string `json:"last_snapshot_at"`
}

// DecisionHistoryResponse wraps paged decision history.
type DecisionHistoryResponse struct {
	Decisions []DecisionHistoryRecord `json:"decisions"`
	Count     int                     `json:"count"`
	Total     int                     `json:"total"`
}

// AlertHistoryRecord is a persisted alert snapshot.
type AlertHistoryRecord struct {
	ID             int64  `json:"id"`
	DedupeKey      string `json:"dedupe_key"`
	AlertID        int64  `json:"alert_id"`
	Scenario       string `json:"scenario"`
	Scope          string `json:"scope"`
	Value          string `json:"value"`
	Origin         string `json:"origin"`
	Type           string `json:"type,omitempty"`
	EventsCount    int    `json:"events_count"`
	StartAt        string `json:"start_at,omitempty"`
	StopAt         string `json:"stop_at,omitempty"`
	IsStale        bool   `json:"is_stale"`
	FirstSeenAt    string `json:"first_seen_at"`
	LastSeenAt     string `json:"last_seen_at"`
	StaleAt        string `json:"stale_at,omitempty"`
	LastSnapshotAt string `json:"last_snapshot_at"`
}

// AlertHistoryResponse wraps paged alert history.
type AlertHistoryResponse struct {
	Alerts []AlertHistoryRecord `json:"alerts"`
	Count  int                  `json:"count"`
	Total  int                  `json:"total"`
}

// RepeatedOffender describes a value seen repeatedly in decisions.
type RepeatedOffender struct {
	Value           string `json:"value"`
	Scope           string `json:"scope"`
	HitCount        int    `json:"hit_count"`
	WindowDays      int    `json:"window_days"`
	FirstDecisionAt string `json:"first_decision_at"`
	LastDecisionAt  string `json:"last_decision_at"`
	LastNotifiedAt  string `json:"last_notified_at,omitempty"`
}

// ReapplyDecisionRequest re-inserts a historical decision.
type ReapplyDecisionRequest struct {
	ID       int64  `json:"id"`
	Type     string `json:"type"`
	Duration string `json:"duration"`
	Reason   string `json:"reason,omitempty"`
}

// BulkReapplyDecisionsRequest re-inserts multiple historical decisions.
type BulkReapplyDecisionsRequest struct {
	IDs      []int64 `json:"ids"`
	Type     string  `json:"type"`
	Duration string  `json:"duration"`
	Reason   string  `json:"reason,omitempty"`
}

// BulkReapplyResult reports bulk reapply outcomes.
type BulkReapplyResult struct {
	Succeeded     int      `json:"succeeded"`
	Failed        int      `json:"failed"`
	AlreadyActive int      `json:"already_active,omitempty"`
	DecisionIDs   []int64  `json:"decision_ids,omitempty"`
	Errors        []string `json:"errors,omitempty"`
}

// HistoryStats reports aggregate history counts.
type HistoryStats struct {
	TotalDecisions        int `json:"total_decisions"`
	ActiveDecisions       int `json:"active_decisions"`
	TotalAlerts           int `json:"total_alerts"`
	ActiveAlerts          int `json:"active_alerts"`
	RepeatedOffenderCount int `json:"repeated_offender_count"`
}

// HistoryActivityBucket is one history activity bucket.
type HistoryActivityBucket struct {
	Timestamp string `json:"ts"`
	Alerts    int    `json:"alerts"`
	Decisions int    `json:"decisions"`
}

// HistoryActivityResponse reports bucketed history activity.
type HistoryActivityResponse struct {
	Window           string                  `json:"window"`
	Bucket           string                  `json:"bucket"`
	Buckets          []HistoryActivityBucket `json:"buckets"`
	GeneratedAt      string                  `json:"generated_at"`
	LatestSnapshotAt *string                 `json:"latest_snapshot_at"`
}
