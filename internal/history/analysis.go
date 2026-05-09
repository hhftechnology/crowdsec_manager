package history

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"crowdsec-manager/internal/models"
)

const (
	decisionTypeAnalysisLimit = 5
	topIPAnalysisLimit        = 10
)

var historyDurationPattern = regexp.MustCompile(`^(\d+)([smhdw])$`)

type decisionHistoryWhereInput struct {
	Filter models.DecisionHistoryFilter
	Now    time.Time
}

type historyWhereClause struct {
	SQL  string
	Args []interface{}
}

type historyWhereBuilder struct {
	parts []string
	args  []interface{}
}

func (b *historyWhereBuilder) add(clause string, args ...interface{}) {
	b.parts = append(b.parts, clause)
	b.args = append(b.args, args...)
}

func (b historyWhereBuilder) clause() historyWhereClause {
	return historyWhereClause{
		SQL:  strings.Join(b.parts, " AND "),
		Args: b.args,
	}
}

// GetDecisionHistoryAnalysis returns history-backed decision chart aggregates.
func (s *Store) GetDecisionHistoryAnalysis(ctx context.Context, filter models.DecisionHistoryFilter) (*models.DecisionHistoryAnalysisResponse, error) {
	if s == nil || s.db == nil {
		return nil, ErrStoreUnavailable
	}

	ready, latestSnapshotAt, err := s.decisionHistoryReadiness(ctx)
	if err != nil {
		return nil, fmt.Errorf("load decision history readiness: %w", err)
	}

	where := buildDecisionHistoryWhere(decisionHistoryWhereInput{
		Filter: filter,
		Now:    time.Now().UTC(),
	})

	count, err := s.countDecisionHistory(ctx, where)
	if err != nil {
		return nil, fmt.Errorf("count decision history: %w", err)
	}

	overTime, err := s.listDecisionHistoryOverTime(ctx, where)
	if err != nil {
		return nil, fmt.Errorf("load decision history timeline: %w", err)
	}

	decisionTypes, err := s.listDecisionHistoryBreakdown(ctx, decisionHistoryBreakdownInput{
		Where:  where,
		Field:  "type",
		Limit:  decisionTypeAnalysisLimit,
		IPOnly: false,
	})
	if err != nil {
		return nil, fmt.Errorf("load decision type breakdown: %w", err)
	}

	topIPs, err := s.listDecisionHistoryBreakdown(ctx, decisionHistoryBreakdownInput{
		Where:  where,
		Field:  "value",
		Limit:  topIPAnalysisLimit,
		IPOnly: true,
	})
	if err != nil {
		return nil, fmt.Errorf("load top IP breakdown: %w", err)
	}

	return &models.DecisionHistoryAnalysisResponse{
		Ready:            ready,
		Count:            count,
		LatestSnapshotAt: latestSnapshotAt,
		OverTime:         overTime,
		DecisionTypes:    decisionTypes,
		TopIPs:           topIPs,
	}, nil
}

func (s *Service) GetDecisionHistoryAnalysis(ctx context.Context, filter models.DecisionHistoryFilter) (*models.DecisionHistoryAnalysisResponse, error) {
	if s == nil || s.store == nil {
		return nil, ErrStoreUnavailable
	}
	return s.store.GetDecisionHistoryAnalysis(ctx, filter)
}

func buildDecisionHistoryWhere(in decisionHistoryWhereInput) historyWhereClause {
	filter := in.Filter
	builder := historyWhereBuilder{parts: []string{"1=1"}}

	if filter.Stale != nil {
		stale := 0
		if *filter.Stale {
			stale = 1
		}
		builder.add("is_stale = ?", stale)
	}
	if filter.Value != "" {
		builder.add("value LIKE ?", "%"+filter.Value+"%")
	}
	if filter.Scenario != "" {
		builder.add("scenario LIKE ?", "%"+filter.Scenario+"%")
	}
	if filter.Since != "" {
		builder.add("datetime(created_at) >= datetime(?)", resolveHistoryTimeFilter(filter.Since, in.Now))
	}
	if filter.Until != "" {
		builder.add("datetime(created_at) <= datetime(?)", resolveHistoryTimeFilter(filter.Until, in.Now))
	}
	if filter.Type != "" && filter.Type != "all" {
		builder.add("LOWER(type) = LOWER(?)", filter.Type)
	}
	if filter.Scope != "" && filter.Scope != "all" {
		builder.add("LOWER(scope) = LOWER(?)", filter.Scope)
	}
	if filter.Origin != "" && filter.Origin != "all" {
		builder.add("LOWER(origin) = LOWER(?)", filter.Origin)
	}
	if filter.IP != "" {
		builder.add("LOWER(scope) = 'ip'")
		builder.add("value = ?", filter.IP)
	}
	if filter.Range != "" {
		builder.add("LOWER(scope) = 'range'")
		builder.add("value = ?", filter.Range)
	}

	return builder.clause()
}

func resolveHistoryTimeFilter(raw string, now time.Time) string {
	trimmed := strings.TrimSpace(strings.ToLower(raw))
	if trimmed == "" {
		return raw
	}

	if d, ok := parseHistoryDuration(trimmed); ok {
		return now.UTC().Add(-d).Format(time.RFC3339)
	}

	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02", "2006-01-02 15:04:05"} {
		parsed, err := time.Parse(layout, raw)
		if err == nil {
			return parsed.UTC().Format(time.RFC3339)
		}
	}

	return raw
}

func parseHistoryDuration(raw string) (time.Duration, bool) {
	matches := historyDurationPattern.FindStringSubmatch(raw)
	if matches == nil {
		d, err := time.ParseDuration(raw)
		return d, err == nil && d > 0
	}

	value, err := strconv.Atoi(matches[1])
	if err != nil || value <= 0 {
		return 0, false
	}

	switch matches[2] {
	case "s":
		return time.Duration(value) * time.Second, true
	case "m":
		return time.Duration(value) * time.Minute, true
	case "h":
		return time.Duration(value) * time.Hour, true
	case "d":
		return time.Duration(value) * 24 * time.Hour, true
	case "w":
		return time.Duration(value) * 7 * 24 * time.Hour, true
	default:
		return 0, false
	}
}

func (s *Store) decisionHistoryReadiness(ctx context.Context) (bool, *string, error) {
	var total int
	var latest sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(1), COALESCE(MAX(strftime('%Y-%m-%dT%H:%M:%SZ', datetime(last_snapshot_at))), '')
		FROM decision_history
	`).Scan(&total, &latest)
	if err != nil {
		return false, nil, err
	}
	if latest.Valid && latest.String != "" {
		value := latest.String
		return true, &value, nil
	}
	return total > 0, nil, nil
}

func (s *Store) countDecisionHistory(ctx context.Context, where historyWhereClause) (int, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(1) FROM decision_history WHERE "+where.SQL, where.Args...).Scan(&count)
	return count, err
}

func (s *Store) listDecisionHistoryOverTime(ctx context.Context, where historyWhereClause) ([]models.HistoryChartPoint, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT strftime('%Y-%m-%dT00:00:00Z', datetime(created_at)) AS bucket_start, COUNT(1)
		FROM decision_history
		WHERE `+where.SQL+`
			AND datetime(created_at) IS NOT NULL
		GROUP BY bucket_start
		ORDER BY bucket_start ASC
	`, where.Args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	points := []models.HistoryChartPoint{}
	for rows.Next() {
		var point models.HistoryChartPoint
		if err := rows.Scan(&point.Timestamp, &point.Value); err != nil {
			return nil, err
		}
		points = append(points, point)
	}
	return points, rows.Err()
}

type decisionHistoryBreakdownInput struct {
	Where  historyWhereClause
	Field  string
	Limit  int
	IPOnly bool
}

func (s *Store) listDecisionHistoryBreakdown(ctx context.Context, in decisionHistoryBreakdownInput) ([]models.HistoryBreakdownItem, error) {
	whereSQL := in.Where.SQL + " AND " + in.Field + " <> ''"
	args := append([]interface{}{}, in.Where.Args...)
	if in.IPOnly {
		whereSQL += " AND LOWER(scope) = 'ip'"
	}
	args = append(args, in.Limit)

	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(`
		SELECT %s AS name, COUNT(1) AS value
		FROM decision_history
		WHERE %s
		GROUP BY %s
		ORDER BY COUNT(1) DESC, name ASC
		LIMIT ?
	`, in.Field, whereSQL, in.Field), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []models.HistoryBreakdownItem{}
	for rows.Next() {
		var item models.HistoryBreakdownItem
		if err := rows.Scan(&item.Name, &item.Value); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
