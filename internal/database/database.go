package database

import (
	"crowdsec-manager/internal/models"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

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

	// Initialize proxy settings table and migrate existing data
	if err := d.CreateProxySettingsTable(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize proxy settings: %w", err)
	}

	// Migrate existing Traefik settings to new proxy format
	if err := d.MigrateExistingTraefikSettings(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate existing settings: %w", err)
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
		discord_webhook_id TEXT NOT NULL DEFAULT '',
		discord_webhook_token TEXT NOT NULL DEFAULT '',
		geoapify_key TEXT NOT NULL DEFAULT '',
		cti_key TEXT NOT NULL DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS profile_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		content TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	if _, err := d.db.Exec(createTable); err != nil {
		return fmt.Errorf("failed to create settings table: %w", err)
	}

	// Apply migrations for existing databases with older schemas
	// Errors are intentionally ignored since columns may already exist
	migrations := []string{
		"ALTER TABLE settings ADD COLUMN discord_webhook_id TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE settings ADD COLUMN discord_webhook_token TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE settings ADD COLUMN geoapify_key TEXT NOT NULL DEFAULT ''",
		"ALTER TABLE settings ADD COLUMN cti_key TEXT NOT NULL DEFAULT ''",
	}

	for _, query := range migrations {
		d.db.Exec(query) // Ignore errors - column may already exist
	}

	// Insert default settings row if database is empty
	insertDefaults := `
	INSERT OR IGNORE INTO settings (id, traefik_dynamic_config, traefik_static_config, traefik_access_log, traefik_error_log, crowdsec_acquis_file, discord_webhook_id, discord_webhook_token, geoapify_key, cti_key)
	VALUES (1, '/etc/traefik/dynamic_config.yml', '/etc/traefik/traefik_config.yml', '/var/log/traefik/access.log', '/var/log/traefik/traefik.log', '/etc/crowdsec/acquis.yaml', '', '', '', '');
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
		discord_webhook_id, discord_webhook_token, geoapify_key, cti_key
		FROM settings
		WHERE id = 1
	`).Scan(&settings.ID, &settings.TraefikDynamicConfig, &settings.TraefikStaticConfig,
		&settings.TraefikAccessLog, &settings.TraefikErrorLog, &settings.CrowdSecAcquisFile,
		&settings.DiscordWebhookID, &settings.DiscordWebhookToken, &settings.GeoapifyKey, &settings.CrowdSecCTIKey)

	if err == sql.ErrNoRows {
		// Return sensible defaults if no settings row exists
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

// UpdateSettings updates all application settings in database
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
// Proxy-related database operations

// CreateProxySettingsTable creates the proxy_settings table and migrates existing settings
func (d *Database) CreateProxySettingsTable() error {
	// Create proxy_settings table
	createProxyTable := `
	CREATE TABLE IF NOT EXISTS proxy_settings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		proxy_type TEXT NOT NULL DEFAULT 'traefik',
		container_name TEXT NOT NULL,
		config_paths TEXT NOT NULL DEFAULT '{}',      -- JSON map[string]string
		custom_settings TEXT NOT NULL DEFAULT '{}',   -- JSON map[string]string
		enabled_features TEXT NOT NULL DEFAULT '[]',  -- JSON []string
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	
	if _, err := d.db.Exec(createProxyTable); err != nil {
		return fmt.Errorf("failed to create proxy_settings table: %w", err)
	}

	// Add new columns to settings table for proxy configuration
	proxyMigrations := []string{
		"ALTER TABLE settings ADD COLUMN proxy_type TEXT NOT NULL DEFAULT 'traefik'",
		"ALTER TABLE settings ADD COLUMN proxy_enabled INTEGER NOT NULL DEFAULT 1",
		"ALTER TABLE settings ADD COLUMN compose_mode TEXT NOT NULL DEFAULT 'single'",
	}

	for _, query := range proxyMigrations {
		d.db.Exec(query) // Ignore errors - column may already exist
	}

	return nil
}

// MigrateExistingTraefikSettings migrates existing Traefik settings to proxy_settings table
func (d *Database) MigrateExistingTraefikSettings() error {
	// Check if migration has already been done
	var count int
	err := d.db.QueryRow("SELECT COUNT(*) FROM proxy_settings WHERE id = 1").Scan(&count)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("failed to check migration status: %w", err)
	}
	
	if count > 0 {
		// Migration already done
		return nil
	}

	// Get existing settings
	settings, err := d.GetSettings()
	if err != nil {
		return fmt.Errorf("failed to get existing settings: %w", err)
	}

	// Create JSON for config paths
	configPaths := fmt.Sprintf(`{
		"dynamic": "%s",
		"static": "%s",
		"access_log": "%s",
		"error_log": "%s"
	}`, settings.TraefikDynamicConfig, settings.TraefikStaticConfig, 
		settings.TraefikAccessLog, settings.TraefikErrorLog)

	// Insert migrated settings
	_, err = d.db.Exec(`
		INSERT OR IGNORE INTO proxy_settings (id, proxy_type, container_name, config_paths, custom_settings, enabled_features)
		VALUES (1, 'traefik', 'traefik', ?, '{}', '["whitelist","captcha","logs","bouncer","health","appsec"]')
	`, configPaths)

	return err
}

// GetProxySettings retrieves proxy settings from database
func (d *Database) GetProxySettings() (*models.ProxySettings, error) {
	settings := &models.ProxySettings{}
	var configPathsJSON, customSettingsJSON, enabledFeaturesJSON string
	
	err := d.db.QueryRow(`
		SELECT id, proxy_type, container_name, config_paths, custom_settings, enabled_features, created_at, updated_at
		FROM proxy_settings
		WHERE id = 1
	`).Scan(&settings.ID, &settings.ProxyType, &settings.ContainerName,
		&configPathsJSON, &customSettingsJSON, &enabledFeaturesJSON,
		&settings.CreatedAt, &settings.UpdatedAt)

	if err == sql.ErrNoRows {
		// Return default settings for Traefik
		return &models.ProxySettings{
			ID:            1,
			ProxyType:     "traefik",
			ContainerName: "traefik",
			ConfigPaths: map[string]string{
				"dynamic":    "/etc/traefik/dynamic_config.yml",
				"static":     "/etc/traefik/traefik_config.yml",
				"access_log": "/var/log/traefik/access.log",
				"error_log":  "/var/log/traefik/traefik.log",
			},
			CustomSettings:  make(map[string]string),
			EnabledFeatures: []string{"whitelist", "captcha", "logs", "bouncer", "health", "appsec"},
		}, nil
	}

	if err != nil {
		return nil, err
	}

	// Parse JSON fields (simplified parsing for now)
	settings.ConfigPaths = make(map[string]string)
	settings.CustomSettings = make(map[string]string)
	settings.EnabledFeatures = []string{}

	// TODO: Implement proper JSON parsing
	// For now, return basic structure
	return settings, nil
}

// UpdateProxySettings updates proxy settings in database
func (d *Database) UpdateProxySettings(settings *models.ProxySettings) error {
	// TODO: Implement JSON marshaling for map fields
	configPathsJSON := "{}"
	customSettingsJSON := "{}"
	enabledFeaturesJSON := "[]"

	_, err := d.db.Exec(`
		UPDATE proxy_settings
		SET proxy_type = ?,
		    container_name = ?,
		    config_paths = ?,
		    custom_settings = ?,
		    enabled_features = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE id = 1
	`, settings.ProxyType, settings.ContainerName,
		configPathsJSON, customSettingsJSON, enabledFeaturesJSON)
	
	return err
}

// CreateProxySettings creates new proxy settings
func (d *Database) CreateProxySettings(settings *models.ProxySettings) error {
	// TODO: Implement JSON marshaling for map fields
	configPathsJSON := "{}"
	customSettingsJSON := "{}"
	enabledFeaturesJSON := "[]"

	_, err := d.db.Exec(`
		INSERT INTO proxy_settings (proxy_type, container_name, config_paths, custom_settings, enabled_features)
		VALUES (?, ?, ?, ?, ?)
	`, settings.ProxyType, settings.ContainerName,
		configPathsJSON, customSettingsJSON, enabledFeaturesJSON)
	
	return err
}