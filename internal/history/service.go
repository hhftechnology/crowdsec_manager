package history

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/messaging"
	"crowdsec-manager/internal/models"
)

const (
	defaultSyncInterval    = 5 * time.Minute
	defaultCleanupInterval = 24 * time.Hour
	repeatedNotifyCooldown = 24 * time.Hour
)

// CrowdSecExecutor executes commands in CrowdSec container.
type CrowdSecExecutor interface {
	ExecCommand(containerName string, cmd []string) (string, error)
}

// Service performs periodic history sync and offender detection.
type Service struct {
	store    *Store
	executor CrowdSecExecutor
	cfg      *config.Config
	hub      *messaging.Hub

	syncInterval    time.Duration
	cleanupInterval time.Duration

	stop chan struct{}
	wg   sync.WaitGroup
}

func NewService(store *Store, executor CrowdSecExecutor, cfg *config.Config, hub *messaging.Hub) *Service {
	return &Service{
		store:           store,
		executor:        executor,
		cfg:             cfg,
		hub:             hub,
		syncInterval:    defaultSyncInterval,
		cleanupInterval: defaultCleanupInterval,
		stop:            make(chan struct{}),
	}
}

func (s *Service) Start() {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		ctx := context.Background()
		if err := s.SyncOnce(ctx); err != nil {
			logger.Warn("Initial history sync failed", "error", err)
		}
		if err := s.CleanupRetention(ctx); err != nil {
			logger.Warn("Initial history cleanup failed", "error", err)
		}

		syncTicker := time.NewTicker(s.syncInterval)
		cleanupTicker := time.NewTicker(s.cleanupInterval)
		defer syncTicker.Stop()
		defer cleanupTicker.Stop()

		for {
			select {
			case <-s.stop:
				return
			case <-syncTicker.C:
				if err := s.SyncOnce(ctx); err != nil {
					logger.Warn("History sync failed", "error", err)
				}
			case <-cleanupTicker.C:
				if err := s.CleanupRetention(ctx); err != nil {
					logger.Warn("History cleanup failed", "error", err)
				}
			}
		}
	}()
}

func (s *Service) Stop() {
	close(s.stop)
	s.wg.Wait()
}

func (s *Service) SyncOnce(ctx context.Context) error {
	if s.executor == nil {
		return fmt.Errorf("history service executor is nil")
	}
	if s.cfg == nil {
		return fmt.Errorf("history service config is nil")
	}

	snapshotAt := time.Now().UTC()

	decisionsOutput, err := s.executor.ExecCommand(
		s.cfg.CrowdsecContainerName,
		[]string{"cscli", "decisions", "list", "-o", "json"},
	)
	if err != nil {
		return fmt.Errorf("fetch decisions: %w", err)
	}
	decisions, err := parseDecisionsOutput(decisionsOutput)
	if err != nil {
		return fmt.Errorf("parse decisions: %w", err)
	}

	decisionInputs := make([]UpsertDecisionInput, 0, len(decisions))
	for _, d := range decisions {
		decisionInputs = append(decisionInputs, UpsertDecisionInput{
			Decision:   d,
			SnapshotAt: snapshotAt,
		})
	}
	if err := s.store.UpsertDecisionSnapshots(ctx, decisionInputs); err != nil {
		return fmt.Errorf("upsert decision snapshots: %w", err)
	}
	if err := s.store.MarkMissingDecisionSnapshotsStale(ctx, snapshotAt); err != nil {
		return fmt.Errorf("mark missing decisions stale: %w", err)
	}

	alertsOutput, err := s.executor.ExecCommand(
		s.cfg.CrowdsecContainerName,
		[]string{"cscli", "alerts", "list", "-o", "json"},
	)
	if err != nil {
		return fmt.Errorf("fetch alerts: %w", err)
	}
	alerts, err := parseAlertsOutput(alertsOutput)
	if err != nil {
		return fmt.Errorf("parse alerts: %w", err)
	}

	alertInputs := make([]UpsertAlertInput, 0, len(alerts))
	for _, a := range alerts {
		alertInputs = append(alertInputs, UpsertAlertInput{
			Alert:      a,
			SnapshotAt: snapshotAt,
		})
	}
	if err := s.store.UpsertAlertSnapshots(ctx, alertInputs); err != nil {
		return fmt.Errorf("upsert alert snapshots: %w", err)
	}
	if err := s.store.MarkMissingAlertSnapshotsStale(ctx, snapshotAt); err != nil {
		return fmt.Errorf("mark missing alerts stale: %w", err)
	}

	if err := s.emitRepeatedOffenders(ctx, snapshotAt); err != nil {
		return fmt.Errorf("emit repeated offenders: %w", err)
	}

	return nil
}

func (s *Service) emitRepeatedOffenders(ctx context.Context, now time.Time) error {
	offenders, err := s.store.ListRepeatedOffenders(ctx)
	if err != nil {
		return err
	}

	for _, offender := range offenders {
		notify, err := s.store.RecordRepeatedOffenderEvent(ctx, offender, now, repeatedNotifyCooldown)
		if err != nil {
			logger.Warn("Failed to record repeated offender event", "value", offender.Value, "scope", offender.Scope, "error", err)
			continue
		}
		if !notify || s.hub == nil {
			continue
		}

		s.hub.Broadcast(messaging.Event{
			ID:        fmt.Sprintf("repeated-%d-%s", now.UnixNano(), offender.Value),
			Type:      "crowdsec.repeated_offender",
			Timestamp: now,
			Payload:   offender,
		})
	}
	return nil
}

func (s *Service) CleanupRetention(ctx context.Context) error {
	cfg, err := s.store.GetHistoryConfig(ctx)
	if err != nil {
		return err
	}
	return s.store.CleanupRetention(ctx, cfg.RetentionDays)
}

func (s *Service) GetHistoryConfig(ctx context.Context) (*models.HistoryConfig, error) {
	return s.store.GetHistoryConfig(ctx)
}

func (s *Service) UpdateRetentionDays(ctx context.Context, days int) (*models.HistoryConfig, error) {
	return s.store.UpdateRetentionDays(ctx, days)
}

func (s *Service) ListDecisionHistory(ctx context.Context, filter models.DecisionHistoryFilter) ([]models.DecisionHistoryRecord, int, error) {
	return s.store.ListDecisionHistory(ctx, filter)
}

func (s *Service) ListAlertHistory(ctx context.Context, filter models.AlertHistoryFilter) ([]models.AlertHistoryRecord, int, error) {
	return s.store.ListAlertHistory(ctx, filter)
}

func (s *Service) ListRepeatedOffenders(ctx context.Context) ([]models.RepeatedOffender, error) {
	return s.store.ListRepeatedOffenders(ctx)
}

func (s *Service) MarkDecisionDeleted(ctx context.Context, decisionID int64, value string) error {
	now := time.Now().UTC()
	if decisionID > 0 {
		return s.store.MarkDecisionStaleByID(ctx, decisionID, now)
	}
	if value != "" {
		return s.store.MarkDecisionStaleByValue(ctx, value, now)
	}
	return nil
}

func (s *Service) MarkAlertDeleted(ctx context.Context, alertID int64) error {
	if alertID <= 0 {
		return nil
	}
	return s.store.MarkAlertStaleByAlertID(ctx, alertID, time.Now().UTC())
}

func (s *Service) GetDecisionHistoryRecord(ctx context.Context, id int64) (*models.DecisionHistoryRecord, error) {
	return s.store.GetDecisionHistoryRecord(ctx, id)
}

func (s *Service) GetHistoryStats(ctx context.Context) (*models.HistoryStats, error) {
	return s.store.GetHistoryStats(ctx)
}

func parseCLIJSONOutput(output string) (interface{}, error) {
	start := firstCLIJSONStartIndex(output)
	if start < 0 {
		return nil, fmt.Errorf("no JSON payload found")
	}

	decoder := json.NewDecoder(strings.NewReader(output[start:]))
	decoder.UseNumber()

	var parsed interface{}
	if err := decoder.Decode(&parsed); err != nil {
		return nil, err
	}
	return parsed, nil
}

func firstCLIJSONStartIndex(output string) int {
	objectStart := strings.Index(output, "{")
	arrayStart := strings.Index(output, "[")
	switch {
	case objectStart == -1:
		return arrayStart
	case arrayStart == -1:
		return objectStart
	case objectStart < arrayStart:
		return objectStart
	default:
		return arrayStart
	}
}

func parseDecisionsOutput(output string) ([]models.Decision, error) {
	output = strings.TrimSpace(output)
	if output == "" || output == "null" {
		return []models.Decision{}, nil
	}

	parsed, err := parseCLIJSONOutput(output)
	if err != nil {
		return nil, err
	}

	items, ok := parsed.([]interface{})
	if !ok {
		return []models.Decision{}, nil
	}

	decisions := make([]models.Decision, 0, len(items))
	for _, item := range items {
		node, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		alertID := asInt64(node["id"])
		alertCreatedAt := asString(node["created_at"])

		if nested, exists := node["decisions"]; exists {
			nestedItems, ok := nested.([]interface{})
			if ok {
				for _, entry := range nestedItems {
					decisionNode, ok := entry.(map[string]interface{})
					if !ok {
						continue
					}
					d := decisionFromNode(decisionNode)
					if d.CreatedAt == "" {
						d.CreatedAt = alertCreatedAt
					}
					d.AlertID = alertID
					if d.Until == "" {
						if until := calculateUntil(d.CreatedAt, d.Duration); !until.IsZero() {
							d.Until = until.Format(time.RFC3339)
						}
					}
					decisions = append(decisions, d)
				}
				continue
			}
		}

		// Fallback: cscli can return direct decision entries without nested decisions.
		if _, hasType := node["type"]; hasType {
			d := decisionFromNode(node)
			if d.CreatedAt == "" {
				d.CreatedAt = alertCreatedAt
			}
			d.AlertID = alertID
			if d.Until == "" {
				if until := calculateUntil(d.CreatedAt, d.Duration); !until.IsZero() {
					d.Until = until.Format(time.RFC3339)
				}
			}
			decisions = append(decisions, d)
		}
	}

	return decisions, nil
}

func parseAlertsOutput(output string) ([]AlertSnapshot, error) {
	output = strings.TrimSpace(output)
	if output == "" || output == "null" {
		return []AlertSnapshot{}, nil
	}

	parsed, err := parseCLIJSONOutput(output)
	if err != nil {
		return nil, err
	}

	items, ok := parsed.([]interface{})
	if !ok {
		return []AlertSnapshot{}, nil
	}

	alerts := make([]AlertSnapshot, 0, len(items))
	for _, item := range items {
		node, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		alerts = append(alerts, AlertSnapshot{
			ID:          asInt64(node["id"]),
			Scenario:    asString(node["scenario"]),
			Scope:       asString(node["scope"]),
			Value:       asString(node["value"]),
			Origin:      asString(node["origin"]),
			Type:        asString(node["type"]),
			EventsCount: int(asInt64(node["events_count"])),
			StartAt:     asString(node["start_at"]),
			StopAt:      asString(node["stop_at"]),
		})
	}
	return alerts, nil
}

func decisionFromNode(node map[string]interface{}) models.Decision {
	decision := models.Decision{
		ID:        asInt64(node["id"]),
		Origin:    asString(node["origin"]),
		Type:      asString(node["type"]),
		Scope:     asString(node["scope"]),
		Value:     asString(node["value"]),
		Duration:  asString(node["duration"]),
		Scenario:  asString(node["scenario"]),
		CreatedAt: asString(node["created_at"]),
		Until:     asString(node["until"]),
	}
	if decision.Scenario == "" {
		decision.Scenario = asString(node["reason"])
	}
	return decision
}

func asString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	default:
		return ""
	}
}

func asInt64(v interface{}) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case float64:
		return int64(t)
	case json.Number:
		if parsed, err := t.Int64(); err == nil {
			return parsed
		}
		if asFloat, err := t.Float64(); err == nil {
			return int64(asFloat)
		}
	case string:
		if parsed, err := strconv.ParseInt(t, 10, 64); err == nil {
			return parsed
		}
	}
	return 0
}

func calculateUntil(createdAtStr, durationStr string) time.Time {
	if createdAtStr == "" || durationStr == "" {
		return time.Time{}
	}

	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05 +0000 UTC",
	}

	var createdAt time.Time
	for _, format := range formats {
		if parsed, err := time.Parse(format, createdAtStr); err == nil {
			createdAt = parsed
			break
		}
	}
	if createdAt.IsZero() {
		return time.Time{}
	}

	duration, err := time.ParseDuration(durationStr)
	if err != nil {
		return time.Time{}
	}
	return createdAt.Add(duration)
}
