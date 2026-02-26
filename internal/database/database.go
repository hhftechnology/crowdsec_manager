package database

import (
	"crowdsec-manager/internal/models"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3" // SQLite driver
)

// Database wraps the SQL database connection with helper methods
type Database struct {
	db *sql.DB
}

// Settings represents application settings stored in the database
type Settings struct {
	ID                   int
	TraefikDynamicConfig string
	TraefikStaticConfig  string
	TraefikAccessLog     string
	TraefikErrorLog      string
	CrowdSecAcquisFile   string
	EnrollDisableContext bool
	DiscordWebhookID     string
	DiscordWebhookToken  string
	GeoapifyKey          string
	CrowdSecCTIKey       string
}

// New creates a new SQLite database connection and initializes schema
// Creates parent directories if they don't exist
func New(dbPath string) (*Database, error) {
	// Ensure parent directory exists before opening database
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	// Open SQLite database with default settings
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	d := &Database{db: db}

	// Initialize schema and migrate existing databases
	if err := d.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return d, nil
}

// Close closes the database connection gracefully
func (d *Database) Close() error {
	return d.db.Close()
}

// initSchema initializes the database schema with automatic migrations
// Handles both fresh installations and upgrades from older schema versions
func (d *Database) initSchema() error {
	// Create settings table with full schema for fresh installs
	createTable := `
	CREATE TABLE IF NOT EXISTS settings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		traefik_dynamic_config TEXT NOT NULL DEFAULT '/etc/traefik/dynamic_config.yml',
		traefik_static_config TEXT NOT NULL DEFAULT '/etc/traefik/traefik_config.yml',
		traefik_access_log TEXT NOT NULL DEFAULT '/var/log/traefik/access.log',
		traefik_error_log TEXT NOT NULL DEFAULT '/var/log/traefik/traefik.log',
		crowdsec_acquis_file TEXT NOT NULL DEFAULT '/etc/crowdsec/acquis.yaml',
		enroll_disable_context INTEGER NOT NULL DEFAULT 0,
		discord_webhook_id TEXT NOT NULL DEFAULT '',
		discord_webhook_token TEXT NOT NULL DEFAULT '',
		geoapify_key TEXT NOT NULL DEFAULT '',
		cti_key TEXT NOT NULL DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS profile_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		content TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS config_snapshots (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		config_type TEXT NOT NULL,
		file_path TEXT NOT NULL,
		content TEXT NOT NULL,
		content_hash TEXT NOT NULL,
		source TEXT NOT NULL DEFAULT 'auto',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(config_type, file_path)
	);`
	if _, err := d.db.Exec(createTable); err != nil {
		return fmt.Errorf("failed to create settings table: %w", err)
	}

	createHubTables := `
	CREATE TABLE IF NOT EXISTS hub_preferences (
		category TEXT PRIMARY KEY,
		default_mode TEXT NOT NULL DEFAULT 'direct',
		default_yaml_path TEXT NOT NULL DEFAULT '',
		last_item_name TEXT NOT NULL DEFAULT '',
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS hub_operation_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		category TEXT NOT NULL,
		mode TEXT NOT NULL,
		action TEXT NOT NULL,
		item_name TEXT NOT NULL DEFAULT '',
		yaml_path TEXT NOT NULL DEFAULT '',
		yaml_content TEXT NOT NULL DEFAULT '',
		command TEXT NOT NULL DEFAULT '',
		success INTEGER NOT NULL DEFAULT 0,
		output TEXT NOT NULL DEFAULT '',
		error TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := d.db.Exec(createHubTables); err != nil {
		return fmt.Errorf("failed to create hub tables: %w", err)
	}

	createFeatureConfigTable := `
CREATE TABLE IF NOT EXISTS feature_configs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feature TEXT NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}',
    source TEXT NOT NULL DEFAULT 'user',
    applied INTEGER NOT NULL DEFAULT 0,
    applied_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_feature_configs_feature ON feature_configs(feature);`
	if _, err := d.db.Exec(createFeatureConfigTable); err != nil {
		return fmt.Errorf("failed to create feature_configs table: %w", err)
	}

	// Apply migrations for existing databases with older schemas
	// Errors are intentionally ignored since columns may already exist
	migrations := []string{
		"ALTER TABLE settings ADD COLUMN discord_webhook_id TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE settings ADD COLUMN discord_webhook_token TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE settings ADD COLUMN geoapify_key TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE settings ADD COLUMN cti_key TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE settings ADD COLUMN enroll_disable_context INTEGER NOT NULL DEFAULT 0",
	}

	for _, query := range migrations {
		d.db.Exec(query) // Ignore errors - column may already exist
	}

	// Insert default settings row if database is empty
	insertDefaults := `
	INSERT OR IGNORE INTO settings (id, traefik_dynamic_config, traefik_static_config, traefik_access_log, traefik_error_log, crowdsec_acquis_file, enroll_disable_context, discord_webhook_id, discord_webhook_token, geoapify_key, cti_key)
	VALUES (1, '/etc/traefik/dynamic_config.yml', '/etc/traefik/traefik_config.yml', '/var/log/traefik/access.log', '/var/log/traefik/traefik.log', '/etc/crowdsec/acquis.yaml', 0, '', '', '', '');
	`
	_, err := d.db.Exec(insertDefaults)
	return err
}

// GetSettings retrieves the current application settings from database
// Returns default values if settings row doesn't exist
func (d *Database) GetSettings() (*Settings, error) {
	settings := &Settings{}
	err := d.db.QueryRow(`
		SELECT id, traefik_dynamic_config, traefik_static_config, traefik_access_log, traefik_error_log, crowdsec_acquis_file,
		enroll_disable_context, discord_webhook_id, discord_webhook_token, geoapify_key, cti_key
		FROM settings
		WHERE id = 1
	`).Scan(&settings.ID, &settings.TraefikDynamicConfig, &settings.TraefikStaticConfig,
		&settings.TraefikAccessLog, &settings.TraefikErrorLog, &settings.CrowdSecAcquisFile,
		&settings.EnrollDisableContext, &settings.DiscordWebhookID, &settings.DiscordWebhookToken, &settings.GeoapifyKey, &settings.CrowdSecCTIKey)

	if err == sql.ErrNoRows {
		// Return sensible defaults if no settings row exists
		return &Settings{
			ID:                   1,
			TraefikDynamicConfig: "/etc/traefik/dynamic_config.yml",
			TraefikStaticConfig:  "/etc/traefik/traefik_config.yml",
			TraefikAccessLog:     "/var/log/traefik/access.log",
			TraefikErrorLog:      "/var/log/traefik/traefik.log",
			CrowdSecAcquisFile:   "/etc/crowdsec/acquis.yaml",
			EnrollDisableContext: false,
		}, nil
	}

	return settings, err
}

// UpdateSettings updates all application settings in database
func (d *Database) UpdateSettings(settings *Settings) error {
	_, err := d.db.Exec(`
		UPDATE settings
		SET traefik_dynamic_config = ?,
		    traefik_static_config = ?,
		    traefik_access_log = ?,
		    traefik_error_log = ?,
		    crowdsec_acquis_file = ?,
		    enroll_disable_context = ?,
			discord_webhook_id = ?,
			discord_webhook_token = ?,
			geoapify_key = ?,
			cti_key = ?
		WHERE id = 1
	`, settings.TraefikDynamicConfig, settings.TraefikStaticConfig,
		settings.TraefikAccessLog, settings.TraefikErrorLog, settings.CrowdSecAcquisFile,
		settings.EnrollDisableContext,
		settings.DiscordWebhookID, settings.DiscordWebhookToken, settings.GeoapifyKey, settings.CrowdSecCTIKey)
	return err
}

// GetTraefikDynamicConfigPath retrieves the configured Traefik dynamic config path
// Returns default path on error for backward compatibility
func (d *Database) GetTraefikDynamicConfigPath() (string, error) {
	settings, err := d.GetSettings()
	if err != nil {
		return "/etc/traefik/dynamic_config.yml", err
	}
	return settings.TraefikDynamicConfig, nil
}

// SetTraefikDynamicConfigPath updates only the Traefik dynamic config path
func (d *Database) SetTraefikDynamicConfigPath(path string) error {
	settings, err := d.GetSettings()
	if err != nil {
		settings = &Settings{ID: 1}
	}
	settings.TraefikDynamicConfig = path
	return d.UpdateSettings(settings)
}

// CreateProfileHistory adds a new entry to the profile history
func (d *Database) CreateProfileHistory(content string) error {
	_, err := d.db.Exec(`
		INSERT INTO profile_history (content)
		VALUES (?)
	`, content)
	return err
}

// GetLatestProfileHistory retrieves the most recent profile history entry
func (d *Database) GetLatestProfileHistory() (*models.ProfileHistory, error) {
	history := &models.ProfileHistory{}
	err := d.db.QueryRow(`
		SELECT id, content, created_at
		FROM profile_history
		ORDER BY created_at DESC
		LIMIT 1
	`).Scan(&history.ID, &history.Content, &history.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	return history, err
}

// SaveConfigSnapshot upserts a config snapshot by (config_type, file_path)
func (d *Database) SaveConfigSnapshot(snapshot *models.ConfigSnapshot) error {
	_, err := d.db.Exec(`
		INSERT INTO config_snapshots (config_type, file_path, content, content_hash, source)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(config_type, file_path) DO UPDATE SET
			content = excluded.content,
			content_hash = excluded.content_hash,
			source = excluded.source,
			updated_at = CURRENT_TIMESTAMP
	`, snapshot.ConfigType, snapshot.FilePath, snapshot.Content, snapshot.ContentHash, snapshot.Source)
	return err
}

// GetConfigSnapshot retrieves a config snapshot by type and path
func (d *Database) GetConfigSnapshot(configType, filePath string) (*models.ConfigSnapshot, error) {
	snapshot := &models.ConfigSnapshot{}
	err := d.db.QueryRow(`
		SELECT id, config_type, file_path, content, content_hash, source, created_at, updated_at
		FROM config_snapshots
		WHERE config_type = ? AND file_path = ?
	`, configType, filePath).Scan(
		&snapshot.ID, &snapshot.ConfigType, &snapshot.FilePath,
		&snapshot.Content, &snapshot.ContentHash, &snapshot.Source,
		&snapshot.CreatedAt, &snapshot.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return snapshot, err
}

// GetAllConfigSnapshots returns all stored config snapshots
func (d *Database) GetAllConfigSnapshots() ([]models.ConfigSnapshot, error) {
	rows, err := d.db.Query(`
		SELECT id, config_type, file_path, content, content_hash, source, created_at, updated_at
		FROM config_snapshots
		ORDER BY config_type, file_path
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snapshots []models.ConfigSnapshot
	for rows.Next() {
		var s models.ConfigSnapshot
		if err := rows.Scan(&s.ID, &s.ConfigType, &s.FilePath, &s.Content, &s.ContentHash, &s.Source, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		snapshots = append(snapshots, s)
	}
	return snapshots, rows.Err()
}

// DeleteConfigSnapshot removes a config snapshot by type and path
func (d *Database) DeleteConfigSnapshot(configType, filePath string) error {
	_, err := d.db.Exec(`
		DELETE FROM config_snapshots WHERE config_type = ? AND file_path = ?
	`, configType, filePath)
	return err
}

// GetHubPreference returns a single hub preference row by category.
func (d *Database) GetHubPreference(category string) (*models.HubPreference, error) {
	pref := &models.HubPreference{}
	err := d.db.QueryRow(`
		SELECT category, default_mode, default_yaml_path, last_item_name, updated_at
		FROM hub_preferences
		WHERE category = ?
	`, category).Scan(&pref.Category, &pref.DefaultMode, &pref.DefaultYAMLPath, &pref.LastItemName, &pref.UpdatedAt)
	if err == sql.ErrNoRows {
		return &models.HubPreference{
			Category:        category,
			DefaultMode:     "direct",
			DefaultYAMLPath: "",
			LastItemName:    "",
		}, nil
	}
	return pref, err
}

// ListHubPreferences returns all category preferences.
func (d *Database) ListHubPreferences() ([]models.HubPreference, error) {
	rows, err := d.db.Query(`
		SELECT category, default_mode, default_yaml_path, last_item_name, updated_at
		FROM hub_preferences
		ORDER BY category
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	prefs := []models.HubPreference{}
	for rows.Next() {
		var pref models.HubPreference
		if err := rows.Scan(&pref.Category, &pref.DefaultMode, &pref.DefaultYAMLPath, &pref.LastItemName, &pref.UpdatedAt); err != nil {
			return nil, err
		}
		prefs = append(prefs, pref)
	}
	return prefs, rows.Err()
}

// UpsertHubPreference inserts or updates a preference for a category.
func (d *Database) UpsertHubPreference(pref *models.HubPreference) error {
	if pref == nil {
		return fmt.Errorf("hub preference cannot be nil")
	}
	_, err := d.db.Exec(`
		INSERT INTO hub_preferences (category, default_mode, default_yaml_path, last_item_name, updated_at)
		VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(category) DO UPDATE SET
			default_mode = excluded.default_mode,
			default_yaml_path = excluded.default_yaml_path,
			last_item_name = excluded.last_item_name,
			updated_at = CURRENT_TIMESTAMP
	`, pref.Category, pref.DefaultMode, pref.DefaultYAMLPath, pref.LastItemName)
	return err
}

// CreateHubOperation stores an operation record for auditing.
func (d *Database) CreateHubOperation(op *models.HubOperationRecord) error {
	if op == nil {
		return fmt.Errorf("hub operation cannot be nil")
	}
	success := 0
	if op.Success {
		success = 1
	}
	res, err := d.db.Exec(`
		INSERT INTO hub_operation_history (category, mode, action, item_name, yaml_path, yaml_content, command, success, output, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, op.Category, op.Mode, op.Action, op.ItemName, op.YAMLPath, op.YAMLContent, op.Command, success, op.Output, op.Error)
	if err != nil {
		return err
	}
	if id, err := res.LastInsertId(); err == nil {
		op.ID = id
	}
	return nil
}

// ListHubOperations returns operation history with optional filters.
func (d *Database) ListHubOperations(filter models.HubOperationFilter) ([]models.HubOperationRecord, error) {
	limit := filter.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	var (
		where []string
		args  []interface{}
	)
	if filter.Category != "" {
		where = append(where, "category = ?")
		args = append(args, filter.Category)
	}
	if filter.Mode != "" {
		where = append(where, "mode = ?")
		args = append(args, filter.Mode)
	}
	if filter.Success != nil {
		where = append(where, "success = ?")
		if *filter.Success {
			args = append(args, 1)
		} else {
			args = append(args, 0)
		}
	}

	query := `
		SELECT id, category, mode, action, item_name, yaml_path, yaml_content, command, success, output, error, created_at
		FROM hub_operation_history
	`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := d.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := []models.HubOperationRecord{}
	for rows.Next() {
		var (
			record  models.HubOperationRecord
			success int
		)
		if err := rows.Scan(
			&record.ID, &record.Category, &record.Mode, &record.Action, &record.ItemName,
			&record.YAMLPath, &record.YAMLContent, &record.Command, &success,
			&record.Output, &record.Error, &record.CreatedAt,
		); err != nil {
			return nil, err
		}
		record.Success = success == 1
		records = append(records, record)
	}
	return records, rows.Err()
}

// GetHubOperationByID returns a single operation record.
func (d *Database) GetHubOperationByID(id int64) (*models.HubOperationRecord, error) {
	var (
		record  models.HubOperationRecord
		success int
	)
	err := d.db.QueryRow(`
		SELECT id, category, mode, action, item_name, yaml_path, yaml_content, command, success, output, error, created_at
		FROM hub_operation_history
		WHERE id = ?
	`, id).Scan(
		&record.ID, &record.Category, &record.Mode, &record.Action, &record.ItemName,
		&record.YAMLPath, &record.YAMLContent, &record.Command, &success,
		&record.Output, &record.Error, &record.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	record.Success = success == 1
	return &record, nil
}

// GetFeatureConfig retrieves a feature configuration by feature name.
// Returns nil, nil when no row exists (not an error condition).
func (d *Database) GetFeatureConfig(feature string) (*models.FeatureConfig, error) {
	cfg := &models.FeatureConfig{}
	var applied int
	err := d.db.QueryRow(`
		SELECT id, feature, config_json, source, applied, COALESCE(applied_at, ''), created_at, updated_at
		FROM feature_configs WHERE feature = ?
	`, feature).Scan(&cfg.ID, &cfg.Feature, &cfg.ConfigJSON, &cfg.Source, &applied, &cfg.AppliedAt, &cfg.CreatedAt, &cfg.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cfg.Applied = applied == 1
	return cfg, nil
}

// SaveFeatureConfig upserts a feature configuration keyed on the feature name.
// Resets the applied flag so that changes require a re-apply.
func (d *Database) SaveFeatureConfig(feature, configJSON, source string) error {
	_, err := d.db.Exec(`
		INSERT INTO feature_configs (feature, config_json, source, applied)
		VALUES (?, ?, ?, 0)
		ON CONFLICT(feature) DO UPDATE SET
			config_json = excluded.config_json,
			source      = excluded.source,
			applied     = 0,
			updated_at  = CURRENT_TIMESTAMP
	`, feature, configJSON, source)
	return err
}

// MarkFeatureApplied marks a feature config as successfully applied with a timestamp.
func (d *Database) MarkFeatureApplied(feature string) error {
	_, err := d.db.Exec(`
		UPDATE feature_configs
		SET applied    = 1,
		    applied_at = CURRENT_TIMESTAMP,
		    updated_at = CURRENT_TIMESTAMP
		WHERE feature = ?
	`, feature)
	return err
}
