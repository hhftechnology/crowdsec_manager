package backward_compatibility

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// DatabaseMigrationTestSuite tests database migration integrity
type DatabaseMigrationTestSuite struct {
	testDir string
}

// NewDatabaseMigrationTestSuite creates a new database migration test suite
func NewDatabaseMigrationTestSuite() *DatabaseMigrationTestSuite {
	return &DatabaseMigrationTestSuite{}
}

// TestDatabaseMigrationIntegrity tests database migration from legacy to multi-proxy schema
func TestDatabaseMigrationIntegrity(t *testing.T) {
	suite := NewDatabaseMigrationTestSuite()
	
	// Test legacy schema migration
	t.Run("LegacySchemaMigration", func(t *testing.T) {
		suite.testLegacySchemaMigration(t)
	})
	
	// Test data preservation during migration
	t.Run("DataPreservation", func(t *testing.T) {
		suite.testDataPreservation(t)
	})
	
	// Test migration rollback
	t.Run("MigrationRollback", func(t *testing.T) {
		suite.testMigrationRollback(t)
	})
	
	// Test incremental migrations
	t.Run("IncrementalMigrations", func(t *testing.T) {
		suite.testIncrementalMigrations(t)
	})
}

// testLegacySchemaMigration tests migration from legacy database schema
func (s *DatabaseMigrationTestSuite) testLegacySchemaMigration(t *testing.T) {
	// Create test database with legacy schema
	dbPath := s.createLegacyDatabase(t)
	defer os.Remove(dbPath)
	
	// Apply migration
	if err := s.applyMigration(dbPath); err != nil {
		t.Fatalf("Failed to apply migration: %v", err)
	}
	
	// Verify new schema
	if err := s.verifyNewSchema(dbPath); err != nil {
		t.Errorf("New schema verification failed: %v", err)
	}
	
	// Verify legacy data is preserved
	if err := s.verifyLegacyDataPreserved(dbPath); err != nil {
		t.Errorf("Legacy data not preserved: %v", err)
	}
}

// testDataPreservation tests that existing data is preserved during migration
func (s *DatabaseMigrationTestSuite) testDataPreservation(t *testing.T) {
	// Create database with test data
	dbPath := s.createDatabaseWithTestData(t)
	defer os.Remove(dbPath)
	
	// Record original data
	originalData := s.extractAllData(t, dbPath)
	
	// Apply migration
	if err := s.applyMigration(dbPath); err != nil {
		t.Fatalf("Failed to apply migration: %v", err)
	}
	
	// Verify data integrity
	if err := s.verifyDataIntegrity(t, dbPath, originalData); err != nil {
		t.Errorf("Data integrity check failed: %v", err)
	}
}

// testMigrationRollback tests migration rollback functionality
func (s *DatabaseMigrationTestSuite) testMigrationRollback(t *testing.T) {
	// Create legacy database
	dbPath := s.createLegacyDatabase(t)
	defer os.Remove(dbPath)
	
	// Create backup before migration
	backupPath := dbPath + ".backup"
	if err := s.createBackup(dbPath, backupPath); err != nil {
		t.Fatalf("Failed to create backup: %v", err)
	}
	defer os.Remove(backupPath)
	
	// Apply migration
	if err := s.applyMigration(dbPath); err != nil {
		t.Fatalf("Failed to apply migration: %v", err)
	}
	
	// Simulate migration failure and rollback
	if err := s.rollbackMigration(dbPath, backupPath); err != nil {
		t.Errorf("Failed to rollback migration: %v", err)
	}
	
	// Verify rollback restored original state
	if err := s.verifyLegacySchema(dbPath); err != nil {
		t.Errorf("Rollback did not restore legacy schema: %v", err)
	}
}

// testIncrementalMigrations tests incremental migration steps
func (s *DatabaseMigrationTestSuite) testIncrementalMigrations(t *testing.T) {
	// Test migration from different starting versions
	versions := []struct {
		name    string
		version string
		setup   func(string) error
	}{
		{
			name:    "Version1_0",
			version: "1.0",
			setup:   s.setupVersion1_0Database,
		},
		{
			name:    "Version1_1",
			version: "1.1",
			setup:   s.setupVersion1_1Database,
		},
		{
			name:    "Version1_2",
			version: "1.2",
			setup:   s.setupVersion1_2Database,
		},
	}
	
	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			dbPath := s.createTempDatabase(t)
			defer os.Remove(dbPath)
			
			// Setup database for specific version
			if err := v.setup(dbPath); err != nil {
				t.Fatalf("Failed to setup %s database: %v", v.version, err)
			}
			
			// Apply incremental migrations
			if err := s.applyIncrementalMigrations(dbPath, v.version); err != nil {
				t.Errorf("Failed to apply incremental migrations from %s: %v", v.version, err)
			}
			
			// Verify final schema
			if err := s.verifyNewSchema(dbPath); err != nil {
				t.Errorf("Final schema verification failed for %s: %v", v.version, err)
			}
		})
	}
}

// Helper functions for database operations

// createLegacyDatabase creates a database with legacy schema
func (s *DatabaseMigrationTestSuite) createLegacyDatabase(t *testing.T) string {
	dbPath := s.createTempDatabase(t)
	
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
	
	// Create legacy schema
	legacySchema := `
		CREATE TABLE IF NOT EXISTS settings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			traefik_container_name TEXT NOT NULL DEFAULT 'traefik',
			traefik_dynamic_config TEXT NOT NULL DEFAULT '/etc/traefik/dynamic_config.yml',
			traefik_static_config TEXT NOT NULL DEFAULT '/etc/traefik/traefik_config.yml',
			traefik_access_log TEXT NOT NULL DEFAULT '/var/log/traefik/access.log',
			crowdsec_container_name TEXT NOT NULL DEFAULT 'crowdsec',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		
		INSERT INTO settings (
			traefik_container_name,
			traefik_dynamic_config,
			traefik_static_config,
			traefik_access_log,
			crowdsec_container_name
		) VALUES (
			'traefik-prod',
			'/custom/dynamic.yml',
			'/custom/static.yml',
			'/custom/access.log',
			'crowdsec-prod'
		);
	`
	
	if _, err := db.Exec(legacySchema); err != nil {
		t.Fatalf("Failed to create legacy schema: %v", err)
	}
	
	return dbPath
}

// createDatabaseWithTestData creates a database with comprehensive test data
func (s *DatabaseMigrationTestSuite) createDatabaseWithTestData(t *testing.T) string {
	dbPath := s.createLegacyDatabase(t)
	
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
	
	// Add additional test data
	testData := `
		-- Add more settings records
		INSERT INTO settings (
			traefik_container_name,
			traefik_dynamic_config,
			crowdsec_container_name
		) VALUES (
			'traefik-test',
			'/test/dynamic.yml',
			'crowdsec-test'
		);
		
		-- Create additional legacy tables if they exist
		CREATE TABLE IF NOT EXISTS whitelist (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL UNIQUE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		
		INSERT INTO whitelist (ip) VALUES 
			('192.168.1.100'),
			('10.0.0.50'),
			('172.16.0.25');
	`
	
	if _, err := db.Exec(testData); err != nil {
		t.Fatalf("Failed to create test data: %v", err)
	}
	
	return dbPath
}

// createTempDatabase creates a temporary database file
func (s *DatabaseMigrationTestSuite) createTempDatabase(t *testing.T) string {
	tempFile, err := os.CreateTemp("", "migration_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp database: %v", err)
	}
	tempFile.Close()
	return tempFile.Name()
}

// applyMigration simulates applying database migration
func (s *DatabaseMigrationTestSuite) applyMigration(dbPath string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	
	// Migration SQL - adds new columns and tables
	migrationSQL := `
		-- Add new columns to settings table
		ALTER TABLE settings ADD COLUMN proxy_type TEXT NOT NULL DEFAULT 'traefik';
		ALTER TABLE settings ADD COLUMN proxy_enabled INTEGER NOT NULL DEFAULT 1;
		ALTER TABLE settings ADD COLUMN compose_mode TEXT NOT NULL DEFAULT 'single';
		
		-- Create new proxy_settings table
		CREATE TABLE IF NOT EXISTS proxy_settings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			proxy_type TEXT NOT NULL DEFAULT 'traefik',
			container_name TEXT NOT NULL,
			config_paths TEXT NOT NULL DEFAULT '{}',
			custom_settings TEXT NOT NULL DEFAULT '{}',
			enabled_features TEXT NOT NULL DEFAULT '[]',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		
		-- Migrate data from settings to proxy_settings
		INSERT INTO proxy_settings (
			proxy_type,
			container_name,
			config_paths,
			created_at,
			updated_at
		)
		SELECT 
			'traefik' as proxy_type,
			traefik_container_name as container_name,
			json_object(
				'dynamic', traefik_dynamic_config,
				'static', traefik_static_config,
				'access_log', traefik_access_log
			) as config_paths,
			created_at,
			updated_at
		FROM settings;
		
		-- Update settings table with new values
		UPDATE settings SET 
			proxy_type = 'traefik',
			proxy_enabled = 1,
			compose_mode = 'single';
	`
	
	_, err = db.Exec(migrationSQL)
	return err
}

// verifyNewSchema verifies that the new schema is correctly applied
func (s *DatabaseMigrationTestSuite) verifyNewSchema(dbPath string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	
	// Check that new columns exist in settings table
	settingsColumns := []string{"proxy_type", "proxy_enabled", "compose_mode"}
	for _, column := range settingsColumns {
		var exists bool
		query := `SELECT COUNT(*) > 0 FROM pragma_table_info('settings') WHERE name = ?`
		if err := db.QueryRow(query, column).Scan(&exists); err != nil {
			return fmt.Errorf("failed to check column %s: %v", column, err)
		}
		if !exists {
			return fmt.Errorf("column %s does not exist", column)
		}
	}
	
	// Check that proxy_settings table exists
	var tableExists bool
	query := `SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='proxy_settings'`
	if err := db.QueryRow(query).Scan(&tableExists); err != nil {
		return fmt.Errorf("failed to check proxy_settings table: %v", err)
	}
	if !tableExists {
		return fmt.Errorf("proxy_settings table does not exist")
	}
	
	// Check that proxy_settings has expected columns
	proxySettingsColumns := []string{"proxy_type", "container_name", "config_paths", "custom_settings", "enabled_features"}
	for _, column := range proxySettingsColumns {
		var exists bool
		query := `SELECT COUNT(*) > 0 FROM pragma_table_info('proxy_settings') WHERE name = ?`
		if err := db.QueryRow(query, column).Scan(&exists); err != nil {
			return fmt.Errorf("failed to check proxy_settings column %s: %v", column, err)
		}
		if !exists {
			return fmt.Errorf("proxy_settings column %s does not exist", column)
		}
	}
	
	return nil
}

// verifyLegacyDataPreserved verifies that legacy data is preserved after migration
func (s *DatabaseMigrationTestSuite) verifyLegacyDataPreserved(dbPath string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	
	// Check that original settings data is preserved
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM settings").Scan(&count); err != nil {
		return fmt.Errorf("failed to count settings: %v", err)
	}
	if count == 0 {
		return fmt.Errorf("no settings data found after migration")
	}
	
	// Check that proxy_settings was populated
	if err := db.QueryRow("SELECT COUNT(*) FROM proxy_settings").Scan(&count); err != nil {
		return fmt.Errorf("failed to count proxy_settings: %v", err)
	}
	if count == 0 {
		return fmt.Errorf("proxy_settings not populated during migration")
	}
	
	// Verify specific data migration
	var containerName string
	if err := db.QueryRow("SELECT container_name FROM proxy_settings WHERE id = 1").Scan(&containerName); err != nil {
		return fmt.Errorf("failed to read migrated container name: %v", err)
	}
	if containerName == "" {
		return fmt.Errorf("container name not migrated correctly")
	}
	
	return nil
}

// verifyLegacySchema verifies that the database has the legacy schema
func (s *DatabaseMigrationTestSuite) verifyLegacySchema(dbPath string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	
	// Check that legacy columns exist
	legacyColumns := []string{"traefik_container_name", "traefik_dynamic_config", "traefik_static_config"}
	for _, column := range legacyColumns {
		var exists bool
		query := `SELECT COUNT(*) > 0 FROM pragma_table_info('settings') WHERE name = ?`
		if err := db.QueryRow(query, column).Scan(&exists); err != nil {
			return fmt.Errorf("failed to check legacy column %s: %v", column, err)
		}
		if !exists {
			return fmt.Errorf("legacy column %s does not exist", column)
		}
	}
	
	return nil
}

// extractAllData extracts all data from the database for comparison
func (s *DatabaseMigrationTestSuite) extractAllData(t *testing.T, dbPath string) map[string]interface{} {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
	
	data := make(map[string]interface{})
	
	// Extract settings data
	rows, err := db.Query("SELECT * FROM settings")
	if err != nil {
		t.Fatalf("Failed to query settings: %v", err)
	}
	defer rows.Close()
	
	var settingsData []map[string]interface{}
	columns, _ := rows.Columns()
	
	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range values {
			valuePtrs[i] = &values[i]
		}
		
		if err := rows.Scan(valuePtrs...); err != nil {
			t.Fatalf("Failed to scan row: %v", err)
		}
		
		rowData := make(map[string]interface{})
		for i, col := range columns {
			rowData[col] = values[i]
		}
		settingsData = append(settingsData, rowData)
	}
	
	data["settings"] = settingsData
	
	// Extract whitelist data if it exists
	if s.tableExists(db, "whitelist") {
		rows, err := db.Query("SELECT * FROM whitelist")
		if err == nil {
			defer rows.Close()
			
			var whitelistData []map[string]interface{}
			columns, _ := rows.Columns()
			
			for rows.Next() {
				values := make([]interface{}, len(columns))
				valuePtrs := make([]interface{}, len(columns))
				for i := range values {
					valuePtrs[i] = &values[i]
				}
				
				if err := rows.Scan(valuePtrs...); err == nil {
					rowData := make(map[string]interface{})
					for i, col := range columns {
						rowData[col] = values[i]
					}
					whitelistData = append(whitelistData, rowData)
				}
			}
			
			data["whitelist"] = whitelistData
		}
	}
	
	return data
}

// verifyDataIntegrity verifies that data integrity is maintained after migration
func (s *DatabaseMigrationTestSuite) verifyDataIntegrity(t *testing.T, dbPath string, originalData map[string]interface{}) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	
	// Verify settings data count
	if settingsData, ok := originalData["settings"].([]map[string]interface{}); ok {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM settings").Scan(&count); err != nil {
			return fmt.Errorf("failed to count settings after migration: %v", err)
		}
		if count != len(settingsData) {
			return fmt.Errorf("settings count mismatch: expected %d, got %d", len(settingsData), count)
		}
	}
	
	// Verify whitelist data if it existed
	if whitelistData, ok := originalData["whitelist"].([]map[string]interface{}); ok {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM whitelist").Scan(&count); err != nil {
			return fmt.Errorf("failed to count whitelist after migration: %v", err)
		}
		if count != len(whitelistData) {
			return fmt.Errorf("whitelist count mismatch: expected %d, got %d", len(whitelistData), count)
		}
	}
	
	return nil
}

// createBackup creates a backup of the database
func (s *DatabaseMigrationTestSuite) createBackup(dbPath, backupPath string) error {
	data, err := os.ReadFile(dbPath)
	if err != nil {
		return err
	}
	return os.WriteFile(backupPath, data, 0644)
}

// rollbackMigration restores database from backup
func (s *DatabaseMigrationTestSuite) rollbackMigration(dbPath, backupPath string) error {
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	return os.WriteFile(dbPath, data, 0644)
}

// tableExists checks if a table exists in the database
func (s *DatabaseMigrationTestSuite) tableExists(db *sql.DB, tableName string) bool {
	var exists bool
	query := `SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name = ?`
	db.QueryRow(query, tableName).Scan(&exists)
	return exists
}

// Version-specific database setup functions

func (s *DatabaseMigrationTestSuite) setupVersion1_0Database(dbPath string) error {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	
	schema := `
		CREATE TABLE settings (
			id INTEGER PRIMARY KEY,
			traefik_container_name TEXT DEFAULT 'traefik',
			crowdsec_container_name TEXT DEFAULT 'crowdsec',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		INSERT INTO settings (traefik_container_name, crowdsec_container_name) 
		VALUES ('traefik', 'crowdsec');
	`
	
	_, err = db.Exec(schema)
	return err
}

func (s *DatabaseMigrationTestSuite) setupVersion1_1Database(dbPath string) error {
	if err := s.setupVersion1_0Database(dbPath); err != nil {
		return err
	}
	
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	
	// Add columns that were added in version 1.1
	schema := `
		ALTER TABLE settings ADD COLUMN traefik_dynamic_config TEXT DEFAULT '/etc/traefik/dynamic_config.yml';
		ALTER TABLE settings ADD COLUMN traefik_static_config TEXT DEFAULT '/etc/traefik/traefik_config.yml';
	`
	
	_, err = db.Exec(schema)
	return err
}

func (s *DatabaseMigrationTestSuite) setupVersion1_2Database(dbPath string) error {
	if err := s.setupVersion1_1Database(dbPath); err != nil {
		return err
	}
	
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	
	// Add columns that were added in version 1.2
	schema := `
		ALTER TABLE settings ADD COLUMN traefik_access_log TEXT DEFAULT '/var/log/traefik/access.log';
		ALTER TABLE settings ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP;
	`
	
	_, err = db.Exec(schema)
	return err
}

// applyIncrementalMigrations applies migrations from a specific version to current
func (s *DatabaseMigrationTestSuite) applyIncrementalMigrations(dbPath, fromVersion string) error {
	// This would contain the logic to apply incremental migrations
	// For testing purposes, we'll apply the full migration
	return s.applyMigration(dbPath)
}