package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

type Database struct {
	db *sql.DB
}

type Settings struct {
	ID                   int
	TraefikDynamicConfig string
	TraefikStaticConfig  string
	TraefikAccessLog     string
	TraefikErrorLog      string
	CrowdSecAcquisFile   string
	DiscordWebhookID     string
	DiscordWebhookToken  string
	GeoapifyKey          string
	CTIKey               string
}

// New creates a new database connection
func New(dbPath string) (*Database, error) {
	// Ensure directory exists
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

// Close closes the database connection
func (d *Database) Close() error {
	return d.db.Close()
}

// initSchema initializes the database schema
func (d *Database) initSchema() error {
	// 1. Create table with full schema if it doesn't exist
	createTable := `
	CREATE TABLE IF NOT EXISTS settings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		traefik_dynamic_config TEXT NOT NULL DEFAULT '/etc/traefik/dynamic_config.yml',
		traefik_static_config TEXT NOT NULL DEFAULT '/etc/traefik/traefik_config.yml',
		traefik_access_log TEXT NOT NULL DEFAULT '/var/log/traefik/access.log',
		traefik_error_log TEXT NOT NULL DEFAULT '/var/log/traefik/traefik.log',
		crowdsec_acquis_file TEXT NOT NULL DEFAULT '/etc/crowdsec/acquis.yaml',
		discord_webhook_id TEXT NOT NULL DEFAULT '',
		discord_webhook_token TEXT NOT NULL DEFAULT '',
		geoapify_key TEXT NOT NULL DEFAULT '',
		cti_key TEXT NOT NULL DEFAULT ''
	);`
	if _, err := d.db.Exec(createTable); err != nil {
		return fmt.Errorf("failed to create settings table: %w", err)
	}

	// 2. Migrate: Add columns if they don't exist (ignoring errors)
	// This is necessary because if the table already existed with the old schema, 
	// CREATE TABLE IF NOT EXISTS does nothing.
	migrations := []string{
		"ALTER TABLE settings ADD COLUMN discord_webhook_id TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE settings ADD COLUMN discord_webhook_token TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE settings ADD COLUMN geoapify_key TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE settings ADD COLUMN cti_key TEXT NOT NULL DEFAULT ''",
	}

	for _, query := range migrations {
		d.db.Exec(query) // Ignore error: column might already exist
	}

	// 3. Insert default settings if not exists
	insertDefaults := `
	INSERT OR IGNORE INTO settings (id, traefik_dynamic_config, traefik_static_config, traefik_access_log, traefik_error_log, crowdsec_acquis_file, discord_webhook_id, discord_webhook_token, geoapify_key, cti_key)
	VALUES (1, '/etc/traefik/dynamic_config.yml', '/etc/traefik/traefik_config.yml', '/var/log/traefik/access.log', '/var/log/traefik/traefik.log', '/etc/crowdsec/acquis.yaml', '', '', '', '');
	`
	_, err := d.db.Exec(insertDefaults)
	return err
}

// GetSettings retrieves the current settings
func (d *Database) GetSettings() (*Settings, error) {
	settings := &Settings{}
	err := d.db.QueryRow(`
		SELECT id, traefik_dynamic_config, traefik_static_config, traefik_access_log, traefik_error_log, crowdsec_acquis_file,
		discord_webhook_id, discord_webhook_token, geoapify_key, cti_key
		FROM settings
		WHERE id = 1
	`).Scan(&settings.ID, &settings.TraefikDynamicConfig, &settings.TraefikStaticConfig,
		&settings.TraefikAccessLog, &settings.TraefikErrorLog, &settings.CrowdSecAcquisFile,
		&settings.DiscordWebhookID, &settings.DiscordWebhookToken, &settings.GeoapifyKey, &settings.CTIKey)

	if err == sql.ErrNoRows {
		// Return defaults
		return &Settings{
			ID:                   1,
			TraefikDynamicConfig: "/etc/traefik/dynamic_config.yml",
			TraefikStaticConfig:  "/etc/traefik/traefik_config.yml",
			TraefikAccessLog:     "/var/log/traefik/access.log",
			TraefikErrorLog:      "/var/log/traefik/traefik.log",
			CrowdSecAcquisFile:   "/etc/crowdsec/acquis.yaml",
		}, nil
	}

	return settings, err
}

// UpdateSettings updates the settings
func (d *Database) UpdateSettings(settings *Settings) error {
	_, err := d.db.Exec(`
		UPDATE settings
		SET traefik_dynamic_config = ?,
		    traefik_static_config = ?,
		    traefik_access_log = ?,
		    traefik_error_log = ?,
		    crowdsec_acquis_file = ?,
			discord_webhook_id = ?,
			discord_webhook_token = ?,
			geoapify_key = ?,
			cti_key = ?
		WHERE id = 1
	`, settings.TraefikDynamicConfig, settings.TraefikStaticConfig,
		settings.TraefikAccessLog, settings.TraefikErrorLog, settings.CrowdSecAcquisFile,
		settings.DiscordWebhookID, settings.DiscordWebhookToken, settings.GeoapifyKey, settings.CTIKey)
	return err
}

// GetTraefikDynamicConfigPath returns the configured dynamic config path
func (d *Database) GetTraefikDynamicConfigPath() (string, error) {
	settings, err := d.GetSettings()
	if err != nil {
		return "/etc/traefik/dynamic_config.yml", err
	}
	return settings.TraefikDynamicConfig, nil
}

// SetTraefikDynamicConfigPath updates the dynamic config path
func (d *Database) SetTraefikDynamicConfigPath(path string) error {
	settings, err := d.GetSettings()
	if err != nil {
		settings = &Settings{ID: 1}
	}
	settings.TraefikDynamicConfig = path
	return d.UpdateSettings(settings)
}
