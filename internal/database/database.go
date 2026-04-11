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

// Database wraps the SQL database connection with helper methods.
type Database struct {
	db *sql.DB
}

// Settings represents application settings stored in the database.
type Settings struct {
	ID                   int
	EnrollDisableContext bool
}

// New creates a new SQLite database connection and initializes schema.
func New(dbPath string) (*Database, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	d := &Database{db: db}
	if err := d.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return d, nil
}

// Close closes the database connection gracefully.
func (d *Database) Close() error {
	return d.db.Close()
}

// initSchema initializes the database schema.
func (d *Database) initSchema() error {
	createCoreTables := `
	CREATE TABLE IF NOT EXISTS settings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		enroll_disable_context INTEGER NOT NULL DEFAULT 0
	);

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
	if _, err := d.db.Exec(createCoreTables); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Migration for older schemas that predate enroll_disable_context.
	d.db.Exec("ALTER TABLE settings ADD COLUMN enroll_disable_context INTEGER NOT NULL DEFAULT 0") //nolint:errcheck

	insertDefaults := `
	INSERT OR IGNORE INTO settings (id, enroll_disable_context)
	VALUES (1, 0);
	`
	_, err := d.db.Exec(insertDefaults)
	return err
}

// GetSettings retrieves the current application settings from database.
func (d *Database) GetSettings() (*Settings, error) {
	settings := &Settings{}
	err := d.db.QueryRow(`
		SELECT id, enroll_disable_context
		FROM settings
		WHERE id = 1
	`).Scan(&settings.ID, &settings.EnrollDisableContext)

	if err == sql.ErrNoRows {
		return &Settings{ID: 1, EnrollDisableContext: false}, nil
	}

	return settings, err
}

// UpdateSettings updates application settings in database.
func (d *Database) UpdateSettings(settings *Settings) error {
	_, err := d.db.Exec(`
		UPDATE settings
		SET enroll_disable_context = ?
		WHERE id = 1
	`, settings.EnrollDisableContext)
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
