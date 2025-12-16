package database

import (
	"fmt"
	"path/filepath"
	"testing"

	"pgregory.net/rapid"
)

// **Feature: multi-proxy-architecture, Property 13: Configuration Migration Integrity**
// **Validates: Requirements 1.5**
func TestConfigurationMigrationIntegrity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Create temporary database for testing
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "test.db")

		// Generate random legacy settings
		legacySettings := &Settings{
			ID:                   1,
			TraefikDynamicConfig: rapid.StringMatching(`^/[a-zA-Z0-9/_.-]+\.yml$`).Draw(t, "dynamicConfig"),
			TraefikStaticConfig:  rapid.StringMatching(`^/[a-zA-Z0-9/_.-]+\.yml$`).Draw(t, "staticConfig"),
			TraefikAccessLog:     rapid.StringMatching(`^/[a-zA-Z0-9/_.-]+\.log$`).Draw(t, "accessLog"),
			TraefikErrorLog:      rapid.StringMatching(`^/[a-zA-Z0-9/_.-]+\.log$`).Draw(t, "errorLog"),
			CrowdSecAcquisFile:   rapid.StringMatching(`^/[a-zA-Z0-9/_.-]+\.yaml$`).Draw(t, "acquisFile"),
			DiscordWebhookID:     rapid.StringMatching(`^[0-9]{18}$`).Draw(t, "webhookID"),
			DiscordWebhookToken:  rapid.StringMatching(`^[a-zA-Z0-9_-]{68}$`).Draw(t, "webhookToken"),
			GeoapifyKey:          rapid.StringMatching(`^[a-f0-9]{32}$`).Draw(t, "geoapifyKey"),
			CrowdSecCTIKey:       rapid.StringMatching(`^[a-f0-9]{32}$`).Draw(t, "ctiKey"),
		}

		// Property 1: Database creation and initialization should succeed
		db, err := New(dbPath)
		if err != nil {
			t.Fatalf("Failed to create database: %v", err)
		}
		defer db.Close()

		// Property 2: Legacy settings should be preserved after migration
		err = db.UpdateSettings(legacySettings)
		if err != nil {
			t.Fatalf("Failed to update legacy settings: %v", err)
		}

		// Verify settings were stored correctly
		retrievedSettings, err := db.GetSettings()
		if err != nil {
			t.Fatalf("Failed to retrieve settings: %v", err)
		}

		// Property 3: All legacy fields should be preserved exactly
		if retrievedSettings.TraefikDynamicConfig != legacySettings.TraefikDynamicConfig {
			t.Errorf("TraefikDynamicConfig mismatch: got %s, want %s", 
				retrievedSettings.TraefikDynamicConfig, legacySettings.TraefikDynamicConfig)
		}
		if retrievedSettings.TraefikStaticConfig != legacySettings.TraefikStaticConfig {
			t.Errorf("TraefikStaticConfig mismatch: got %s, want %s", 
				retrievedSettings.TraefikStaticConfig, legacySettings.TraefikStaticConfig)
		}
		if retrievedSettings.TraefikAccessLog != legacySettings.TraefikAccessLog {
			t.Errorf("TraefikAccessLog mismatch: got %s, want %s", 
				retrievedSettings.TraefikAccessLog, legacySettings.TraefikAccessLog)
		}
		if retrievedSettings.TraefikErrorLog != legacySettings.TraefikErrorLog {
			t.Errorf("TraefikErrorLog mismatch: got %s, want %s", 
				retrievedSettings.TraefikErrorLog, legacySettings.TraefikErrorLog)
		}

		// Property 4: Migration should create proxy_settings entry automatically
		err = db.MigrateExistingTraefikSettings()
		if err != nil {
			t.Fatalf("Migration failed: %v", err)
		}

		// Verify proxy settings were created
		proxySettings, err := db.GetProxySettings()
		if err != nil {
			t.Fatalf("Failed to get proxy settings after migration: %v", err)
		}

		// Property 5: Migrated proxy settings should reflect legacy Traefik configuration
		if proxySettings.ProxyType != "traefik" {
			t.Errorf("Expected proxy type 'traefik', got %s", proxySettings.ProxyType)
		}
		if proxySettings.ContainerName != "traefik" {
			t.Errorf("Expected container name 'traefik', got %s", proxySettings.ContainerName)
		}

		// Property 6: Migration should be idempotent (running twice should not cause errors)
		err = db.MigrateExistingTraefikSettings()
		if err != nil {
			t.Errorf("Second migration run failed: %v", err)
		}

		// Verify settings are still intact after second migration
		finalSettings, err := db.GetSettings()
		if err != nil {
			t.Fatalf("Failed to retrieve settings after second migration: %v", err)
		}

		if finalSettings.TraefikDynamicConfig != legacySettings.TraefikDynamicConfig {
			t.Errorf("Settings corrupted after second migration")
		}
	})
}

// Test database schema creation and table structure
func TestDatabaseSchemaIntegrity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "schema_test.db")

		// Property 1: Database creation should create all required tables
		db, err := New(dbPath)
		if err != nil {
			t.Fatalf("Failed to create database: %v", err)
		}
		defer db.Close()

		// Verify settings table exists and has correct structure
		var tableCount int
		err = db.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='settings'").Scan(&tableCount)
		if err != nil {
			t.Fatalf("Failed to check settings table: %v", err)
		}
		if tableCount != 1 {
			t.Errorf("Settings table not found")
		}

		// Verify proxy_settings table exists
		err = db.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='proxy_settings'").Scan(&tableCount)
		if err != nil {
			t.Fatalf("Failed to check proxy_settings table: %v", err)
		}
		if tableCount != 1 {
			t.Errorf("Proxy_settings table not found")
		}

		// Property 2: Default settings row should be created
		settings, err := db.GetSettings()
		if err != nil {
			t.Fatalf("Failed to get default settings: %v", err)
		}
		if settings.ID != 1 {
			t.Errorf("Default settings row not created correctly")
		}

		// Property 3: All required columns should exist in settings table
		requiredColumns := []string{
			"id", "traefik_dynamic_config", "traefik_static_config", 
			"traefik_access_log", "traefik_error_log", "crowdsec_acquis_file",
			"discord_webhook_id", "discord_webhook_token", "geoapify_key", "cti_key",
		}

		for _, column := range requiredColumns {
			var columnExists int
			query := fmt.Sprintf("SELECT COUNT(*) FROM pragma_table_info('settings') WHERE name='%s'", column)
			err = db.db.QueryRow(query).Scan(&columnExists)
			if err != nil {
				t.Fatalf("Failed to check column %s: %v", column, err)
			}
			if columnExists != 1 {
				t.Errorf("Required column %s not found in settings table", column)
			}
		}

		// Property 4: All required columns should exist in proxy_settings table
		proxyColumns := []string{
			"id", "proxy_type", "container_name", "config_paths", 
			"custom_settings", "enabled_features", "created_at", "updated_at",
		}

		for _, column := range proxyColumns {
			var columnExists int
			query := fmt.Sprintf("SELECT COUNT(*) FROM pragma_table_info('proxy_settings') WHERE name='%s'", column)
			err = db.db.QueryRow(query).Scan(&columnExists)
			if err != nil {
				t.Fatalf("Failed to check proxy column %s: %v", column, err)
			}
			if columnExists != 1 {
				t.Errorf("Required column %s not found in proxy_settings table", column)
			}
		}
	})
}

// Test concurrent access and data integrity
func TestDatabaseConcurrencyIntegrity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "concurrency_test.db")

		db, err := New(dbPath)
		if err != nil {
			t.Fatalf("Failed to create database: %v", err)
		}
		defer db.Close()

		// Generate random settings updates
		numUpdates := rapid.IntRange(5, 20).Draw(t, "numUpdates")
		
		// Property: Concurrent updates should not corrupt data
		done := make(chan bool, numUpdates)
		
		for i := 0; i < numUpdates; i++ {
			go func(updateID int) {
				defer func() { done <- true }()
				
				settings := &Settings{
					ID:                   1,
					TraefikDynamicConfig: fmt.Sprintf("/config/dynamic_%d.yml", updateID),
					TraefikStaticConfig:  fmt.Sprintf("/config/static_%d.yml", updateID),
					TraefikAccessLog:     fmt.Sprintf("/logs/access_%d.log", updateID),
					TraefikErrorLog:      fmt.Sprintf("/logs/error_%d.log", updateID),
					CrowdSecAcquisFile:   fmt.Sprintf("/config/acquis_%d.yaml", updateID),
				}
				
				err := db.UpdateSettings(settings)
				if err != nil {
					t.Errorf("Concurrent update %d failed: %v", updateID, err)
				}
			}(i)
		}

		// Wait for all updates to complete
		for i := 0; i < numUpdates; i++ {
			<-done
		}

		// Property: Database should still be readable and consistent after concurrent updates
		finalSettings, err := db.GetSettings()
		if err != nil {
			t.Fatalf("Failed to read settings after concurrent updates: %v", err)
		}
		
		if finalSettings.ID != 1 {
			t.Errorf("Settings ID corrupted after concurrent updates")
		}
	})
}

// Test error handling and recovery
func TestDatabaseErrorHandling(t *testing.T) {
	// Property: Database operations should handle errors gracefully
	
	// Test with invalid database path
	invalidPath := "/invalid/path/that/does/not/exist/test.db"
	_, err := New(invalidPath)
	if err == nil {
		t.Error("Expected error for invalid database path, got nil")
	}

	// Test with valid database
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "error_test.db")
	
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	
	// Close database and try to use it
	db.Close()
	
	_, err = db.GetSettings()
	if err == nil {
		t.Error("Expected error when using closed database, got nil")
	}
}