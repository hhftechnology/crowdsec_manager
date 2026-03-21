package history

import (
	"context"
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"crowdsec-manager/internal/models"

	_ "github.com/mattn/go-sqlite3"
)

const (
	DefaultRetentionDays = 365
	MinRetentionDays     = 1
	MaxRetentionDays     = 365
	DefaultListLimit     = 50
	MaxListLimit         = 200
	RepeatedWindowDays   = 30
	RepeatedThreshold    = 3
)

// Store persists decisions/alerts history in a dedicated SQLite file.
type Store struct {
	db *sql.DB
}

type UpsertDecisionInput struct {
	Decision   models.Decision
	SnapshotAt time.Time
}

type UpsertAlertInput struct {
	Alert      AlertSnapshot
	SnapshotAt time.Time
}

type AlertSnapshot struct {
	ID          int64
	Scenario    string
	Scope       string
	Value       string
	Origin      string
	Type        string
	EventsCount int
	StartAt     string
	StopAt      string
}

// NewStore creates/open history DB and initializes schema.
func NewStore(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create history db dir: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open history db: %w", err)
	}

	s := &Store{db: db}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("init history schema: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) initSchema() error {
	schema := `
CREATE TABLE IF NOT EXISTS decision_history (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	dedupe_key TEXT NOT NULL UNIQUE,
	decision_id INTEGER NOT NULL DEFAULT 0,
	alert_id INTEGER NOT NULL DEFAULT 0,
	origin TEXT NOT NULL DEFAULT '',
	type TEXT NOT NULL DEFAULT '',
	scope TEXT NOT NULL DEFAULT '',
	value TEXT NOT NULL DEFAULT '',
	duration TEXT NOT NULL DEFAULT '',
	scenario TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL DEFAULT '',
	until_at DATETIME NOT NULL DEFAULT '',
	is_stale INTEGER NOT NULL DEFAULT 0,
	first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	stale_at DATETIME,
	last_snapshot_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS alert_history (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	dedupe_key TEXT NOT NULL UNIQUE,
	alert_id INTEGER NOT NULL DEFAULT 0,
	scenario TEXT NOT NULL DEFAULT '',
	scope TEXT NOT NULL DEFAULT '',
	value TEXT NOT NULL DEFAULT '',
	origin TEXT NOT NULL DEFAULT '',
	type TEXT NOT NULL DEFAULT '',
	events_count INTEGER NOT NULL DEFAULT 0,
	start_at DATETIME NOT NULL DEFAULT '',
	stop_at DATETIME NOT NULL DEFAULT '',
	is_stale INTEGER NOT NULL DEFAULT 0,
	first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	stale_at DATETIME,
	last_snapshot_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS history_config (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	retention_days INTEGER NOT NULL DEFAULT 365,
	updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS repeated_offender_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	fingerprint TEXT NOT NULL UNIQUE,
	value TEXT NOT NULL,
	scope TEXT NOT NULL,
	hit_count INTEGER NOT NULL DEFAULT 0,
	window_days INTEGER NOT NULL DEFAULT 30,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_notified_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_decision_history_value_scope_created_at ON decision_history(value, scope, created_at);
CREATE INDEX IF NOT EXISTS idx_decision_history_stale ON decision_history(is_stale);
CREATE INDEX IF NOT EXISTS idx_decision_history_last_seen ON decision_history(last_seen_at);

CREATE INDEX IF NOT EXISTS idx_alert_history_value_scope_start_at ON alert_history(value, scope, start_at);
CREATE INDEX IF NOT EXISTS idx_alert_history_stale ON alert_history(is_stale);
CREATE INDEX IF NOT EXISTS idx_alert_history_last_seen ON alert_history(last_seen_at);

CREATE INDEX IF NOT EXISTS idx_repeated_offender_value_scope ON repeated_offender_events(value, scope);
`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO history_config(id, retention_days)
		VALUES (1, ?)
	`, DefaultRetentionDays)
	return err
}

func NormalizeRetentionDays(days int) int {
	if days < MinRetentionDays {
		return MinRetentionDays
	}
	if days > MaxRetentionDays {
		return MaxRetentionDays
	}
	return days
}

func normalizeListLimit(limit int) int {
	if limit <= 0 {
		return DefaultListLimit
	}
	if limit > MaxListLimit {
		return MaxListLimit
	}
	return limit
}

func normalizeOffset(offset int) int {
	if offset < 0 {
		return 0
	}
	return offset
}

func DecisionDedupeKey(d models.Decision) string {
	parts := []string{
		fmt.Sprintf("%d", d.AlertID),
		d.Origin,
		d.Type,
		d.Scope,
		d.Value,
		d.Scenario,
		d.CreatedAt,
	}
	sum := sha1.Sum([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}

func AlertDedupeKey(a AlertSnapshot) string {
	if a.ID > 0 {
		return fmt.Sprintf("alert:%d", a.ID)
	}
	parts := []string{
		a.Scenario,
		a.Scope,
		a.Value,
		a.Origin,
		a.StartAt,
	}
	sum := sha1.Sum([]byte(strings.Join(parts, "|")))
	return "alert-hash:" + hex.EncodeToString(sum[:])
}

func (s *Store) GetHistoryConfig(ctx context.Context) (*models.HistoryConfig, error) {
	cfg := &models.HistoryConfig{}
	err := s.db.QueryRowContext(ctx, `
		SELECT retention_days, updated_at
		FROM history_config
		WHERE id = 1
	`).Scan(&cfg.RetentionDays, &cfg.UpdatedAt)
	if err == sql.ErrNoRows {
		return &models.HistoryConfig{RetentionDays: DefaultRetentionDays}, nil
	}
	if err != nil {
		return nil, err
	}
	cfg.RetentionDays = NormalizeRetentionDays(cfg.RetentionDays)
	return cfg, nil
}

func (s *Store) UpdateRetentionDays(ctx context.Context, days int) (*models.HistoryConfig, error) {
	normalized := NormalizeRetentionDays(days)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO history_config(id, retention_days, updated_at)
		VALUES(1, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			retention_days = excluded.retention_days,
			updated_at = CURRENT_TIMESTAMP
	`, normalized)
	if err != nil {
		return nil, err
	}
	return s.GetHistoryConfig(ctx)
}

func (s *Store) UpsertDecisionSnapshots(ctx context.Context, inputs []UpsertDecisionInput) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO decision_history (
			dedupe_key, decision_id, alert_id, origin, type, scope, value, duration, scenario, created_at, until_at,
			is_stale, first_seen_at, last_seen_at, stale_at, last_snapshot_at
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, NULL, ?
		)
		ON CONFLICT(dedupe_key) DO UPDATE SET
			decision_id = excluded.decision_id,
			alert_id = excluded.alert_id,
			origin = excluded.origin,
			type = excluded.type,
			scope = excluded.scope,
			value = excluded.value,
			duration = excluded.duration,
			scenario = excluded.scenario,
			created_at = excluded.created_at,
			until_at = excluded.until_at,
			is_stale = 0,
			last_seen_at = excluded.last_seen_at,
			stale_at = NULL,
			last_snapshot_at = excluded.last_snapshot_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, in := range inputs {
		d := in.Decision
		snapshotAt := in.SnapshotAt.UTC().Format(time.RFC3339)
		if _, err := stmt.ExecContext(
			ctx,
			DecisionDedupeKey(d),
			d.ID,
			d.AlertID,
			d.Origin,
			d.Type,
			d.Scope,
			d.Value,
			d.Duration,
			d.Scenario,
			d.CreatedAt,
			d.Until,
			snapshotAt,
			snapshotAt,
			snapshotAt,
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) UpsertAlertSnapshots(ctx context.Context, inputs []UpsertAlertInput) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO alert_history (
			dedupe_key, alert_id, scenario, scope, value, origin, type, events_count, start_at, stop_at,
			is_stale, first_seen_at, last_seen_at, stale_at, last_snapshot_at
		) VALUES (
			?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, NULL, ?
		)
		ON CONFLICT(dedupe_key) DO UPDATE SET
			alert_id = excluded.alert_id,
			scenario = excluded.scenario,
			scope = excluded.scope,
			value = excluded.value,
			origin = excluded.origin,
			type = excluded.type,
			events_count = excluded.events_count,
			start_at = excluded.start_at,
			stop_at = excluded.stop_at,
			is_stale = 0,
			last_seen_at = excluded.last_seen_at,
			stale_at = NULL,
			last_snapshot_at = excluded.last_snapshot_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, in := range inputs {
		a := in.Alert
		snapshotAt := in.SnapshotAt.UTC().Format(time.RFC3339)
		if _, err := stmt.ExecContext(
			ctx,
			AlertDedupeKey(a),
			a.ID,
			a.Scenario,
			a.Scope,
			a.Value,
			a.Origin,
			a.Type,
			a.EventsCount,
			a.StartAt,
			a.StopAt,
			snapshotAt,
			snapshotAt,
			snapshotAt,
		); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) MarkMissingDecisionSnapshotsStale(ctx context.Context, snapshotAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE decision_history
		SET is_stale = 1, stale_at = ?, last_snapshot_at = ?
		WHERE is_stale = 0 AND last_snapshot_at <> ?
	`, snapshotAt.UTC().Format(time.RFC3339), snapshotAt.UTC().Format(time.RFC3339), snapshotAt.UTC().Format(time.RFC3339))
	return err
}

func (s *Store) MarkMissingAlertSnapshotsStale(ctx context.Context, snapshotAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE alert_history
		SET is_stale = 1, stale_at = ?, last_snapshot_at = ?
		WHERE is_stale = 0 AND last_snapshot_at <> ?
	`, snapshotAt.UTC().Format(time.RFC3339), snapshotAt.UTC().Format(time.RFC3339), snapshotAt.UTC().Format(time.RFC3339))
	return err
}

func (s *Store) MarkDecisionStaleByID(ctx context.Context, decisionID int64, snapshotAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE decision_history
		SET is_stale = 1, stale_at = ?, last_snapshot_at = ?
		WHERE decision_id = ?
	`, snapshotAt.UTC().Format(time.RFC3339), snapshotAt.UTC().Format(time.RFC3339), decisionID)
	return err
}

func (s *Store) MarkDecisionStaleByValue(ctx context.Context, value string, snapshotAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE decision_history
		SET is_stale = 1, stale_at = ?, last_snapshot_at = ?
		WHERE value = ?
	`, snapshotAt.UTC().Format(time.RFC3339), snapshotAt.UTC().Format(time.RFC3339), value)
	return err
}

func (s *Store) MarkAlertStaleByAlertID(ctx context.Context, alertID int64, snapshotAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE alert_history
		SET is_stale = 1, stale_at = ?, last_snapshot_at = ?
		WHERE alert_id = ?
	`, snapshotAt.UTC().Format(time.RFC3339), snapshotAt.UTC().Format(time.RFC3339), alertID)
	return err
}

func (s *Store) CleanupRetention(ctx context.Context, retentionDays int) error {
	normalized := NormalizeRetentionDays(retentionDays)
	window := fmt.Sprintf("-%d days", normalized)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM decision_history
		WHERE datetime(last_seen_at) < datetime('now', ?)
	`, window); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM alert_history
		WHERE datetime(last_seen_at) < datetime('now', ?)
	`, window); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM repeated_offender_events
		WHERE datetime(last_seen_at) < datetime('now', ?)
	`, window); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) ListDecisionHistory(ctx context.Context, filter models.DecisionHistoryFilter) ([]models.DecisionHistoryRecord, int, error) {
	limit := normalizeListLimit(filter.Limit)
	offset := normalizeOffset(filter.Offset)

	where := []string{"1=1"}
	args := []interface{}{}

	if filter.Stale != nil {
		stale := 0
		if *filter.Stale {
			stale = 1
		}
		where = append(where, "is_stale = ?")
		args = append(args, stale)
	}
	if filter.Value != "" {
		where = append(where, "value LIKE ?")
		args = append(args, "%"+filter.Value+"%")
	}
	if filter.Scenario != "" {
		where = append(where, "scenario LIKE ?")
		args = append(args, "%"+filter.Scenario+"%")
	}
	if filter.Since != "" {
		where = append(where, "datetime(created_at) >= datetime(?)")
		args = append(args, filter.Since)
	}

	baseWhere := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM decision_history WHERE "+baseWhere, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			id, dedupe_key, decision_id, alert_id, origin, type, scope, value, duration, scenario,
			created_at, until_at, is_stale, first_seen_at, last_seen_at, COALESCE(stale_at, ''), last_snapshot_at
		FROM decision_history
		WHERE `+baseWhere+`
		ORDER BY datetime(last_seen_at) DESC
		LIMIT ? OFFSET ?
	`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	records := []models.DecisionHistoryRecord{}
	for rows.Next() {
		var r models.DecisionHistoryRecord
		var staleInt int
		if err := rows.Scan(
			&r.ID, &r.DedupeKey, &r.DecisionID, &r.AlertID, &r.Origin, &r.Type, &r.Scope, &r.Value,
			&r.Duration, &r.Scenario, &r.CreatedAt, &r.Until, &staleInt, &r.FirstSeenAt,
			&r.LastSeenAt, &r.StaleAt, &r.LastSnapshotAt,
		); err != nil {
			return nil, 0, err
		}
		r.IsStale = staleInt == 1
		records = append(records, r)
	}

	return records, total, rows.Err()
}

func (s *Store) ListAlertHistory(ctx context.Context, filter models.AlertHistoryFilter) ([]models.AlertHistoryRecord, int, error) {
	limit := normalizeListLimit(filter.Limit)
	offset := normalizeOffset(filter.Offset)

	where := []string{"1=1"}
	args := []interface{}{}

	if filter.Stale != nil {
		stale := 0
		if *filter.Stale {
			stale = 1
		}
		where = append(where, "is_stale = ?")
		args = append(args, stale)
	}
	if filter.Value != "" {
		where = append(where, "value LIKE ?")
		args = append(args, "%"+filter.Value+"%")
	}
	if filter.Scenario != "" {
		where = append(where, "scenario LIKE ?")
		args = append(args, "%"+filter.Scenario+"%")
	}
	if filter.Since != "" {
		where = append(where, "datetime(start_at) >= datetime(?)")
		args = append(args, filter.Since)
	}

	baseWhere := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM alert_history WHERE "+baseWhere, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			id, dedupe_key, alert_id, scenario, scope, value, origin, type, events_count, start_at, stop_at,
			is_stale, first_seen_at, last_seen_at, COALESCE(stale_at, ''), last_snapshot_at
		FROM alert_history
		WHERE `+baseWhere+`
		ORDER BY datetime(last_seen_at) DESC
		LIMIT ? OFFSET ?
	`, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	records := []models.AlertHistoryRecord{}
	for rows.Next() {
		var r models.AlertHistoryRecord
		var staleInt int
		if err := rows.Scan(
			&r.ID, &r.DedupeKey, &r.AlertID, &r.Scenario, &r.Scope, &r.Value, &r.Origin, &r.Type,
			&r.EventsCount, &r.StartAt, &r.StopAt, &staleInt, &r.FirstSeenAt, &r.LastSeenAt, &r.StaleAt, &r.LastSnapshotAt,
		); err != nil {
			return nil, 0, err
		}
		r.IsStale = staleInt == 1
		records = append(records, r)
	}

	return records, total, rows.Err()
}

func (s *Store) ListRepeatedOffenders(ctx context.Context) ([]models.RepeatedOffender, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT
			d.value,
			d.scope,
			COUNT(1) AS hit_count,
			MIN(datetime(d.created_at)) AS first_decision_at,
			MAX(datetime(d.created_at)) AS last_decision_at,
			COALESCE(MAX(datetime(e.last_notified_at)), '')
		FROM decision_history d
		LEFT JOIN repeated_offender_events e
			ON d.value = e.value AND d.scope = e.scope
		WHERE datetime(d.created_at) >= datetime('now', '-30 days')
		GROUP BY d.value, d.scope
		HAVING COUNT(1) >= 3
		ORDER BY hit_count DESC, last_decision_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []models.RepeatedOffender{}
	for rows.Next() {
		var row models.RepeatedOffender
		row.WindowDays = RepeatedWindowDays
		if err := rows.Scan(
			&row.Value,
			&row.Scope,
			&row.HitCount,
			&row.FirstDecisionAt,
			&row.LastDecisionAt,
			&row.LastNotifiedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func fingerprintForOffender(offender models.RepeatedOffender) string {
	raw := fmt.Sprintf("%s|%s|%d|%d", offender.Value, offender.Scope, offender.WindowDays, RepeatedThreshold)
	sum := sha1.Sum([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Store) RecordRepeatedOffenderEvent(ctx context.Context, offender models.RepeatedOffender, now time.Time, cooldown time.Duration) (bool, error) {
	fp := fingerprintForOffender(offender)
	var lastNotified sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT COALESCE(last_notified_at, '')
		FROM repeated_offender_events
		WHERE fingerprint = ?
	`, fp).Scan(&lastNotified)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}

	shouldNotify := true
	if err == nil && lastNotified.Valid && lastNotified.String != "" {
		if t, parseErr := time.Parse(time.RFC3339, lastNotified.String); parseErr == nil {
			shouldNotify = now.Sub(t) >= cooldown
		}
	}

	lastSeen := now.UTC().Format(time.RFC3339)
	lastNotify := ""
	if shouldNotify {
		lastNotify = lastSeen
	}

	_, upsertErr := s.db.ExecContext(ctx, `
		INSERT INTO repeated_offender_events(
			fingerprint, value, scope, hit_count, window_days, created_at, last_seen_at, last_notified_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''))
		ON CONFLICT(fingerprint) DO UPDATE SET
			hit_count = excluded.hit_count,
			window_days = excluded.window_days,
			last_seen_at = excluded.last_seen_at,
			last_notified_at = CASE
				WHEN excluded.last_notified_at IS NULL THEN repeated_offender_events.last_notified_at
				ELSE excluded.last_notified_at
			END
	`, fp, offender.Value, offender.Scope, offender.HitCount, offender.WindowDays, lastSeen, lastSeen, lastNotify)
	if upsertErr != nil {
		return false, upsertErr
	}

	return shouldNotify, nil
}

// GetDecisionHistoryRecord returns a single decision history entry by primary key.
func (s *Store) GetDecisionHistoryRecord(ctx context.Context, id int64) (*models.DecisionHistoryRecord, error) {
	var r models.DecisionHistoryRecord
	var staleInt int
	err := s.db.QueryRowContext(ctx, `
		SELECT
			id, dedupe_key, decision_id, alert_id, origin, type, scope, value, duration, scenario,
			created_at, until_at, is_stale, first_seen_at, last_seen_at, COALESCE(stale_at, ''), last_snapshot_at
		FROM decision_history
		WHERE id = ?
	`, id).Scan(
		&r.ID, &r.DedupeKey, &r.DecisionID, &r.AlertID, &r.Origin, &r.Type, &r.Scope, &r.Value,
		&r.Duration, &r.Scenario, &r.CreatedAt, &r.Until, &staleInt, &r.FirstSeenAt,
		&r.LastSeenAt, &r.StaleAt, &r.LastSnapshotAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.IsStale = staleInt == 1
	return &r, nil
}

// GetHistoryStats returns aggregate counts for the history dashboard.
func (s *Store) GetHistoryStats(ctx context.Context) (*models.HistoryStats, error) {
	var stats models.HistoryStats
	queries := []struct {
		dest  *int
		query string
	}{
		{&stats.TotalDecisions, "SELECT COUNT(1) FROM decision_history"},
		{&stats.ActiveDecisions, "SELECT COUNT(1) FROM decision_history WHERE is_stale = 0"},
		{&stats.TotalAlerts, "SELECT COUNT(1) FROM alert_history"},
		{&stats.ActiveAlerts, "SELECT COUNT(1) FROM alert_history WHERE is_stale = 0"},
		{&stats.RepeatedOffenderCount, "SELECT COUNT(1) FROM repeated_offender_events"},
	}
	for _, q := range queries {
		if err := s.db.QueryRowContext(ctx, q.query).Scan(q.dest); err != nil {
			return nil, err
		}
	}
	return &stats, nil
}
