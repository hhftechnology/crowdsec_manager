package database

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestNew_MigratesLegacySettingsColumns(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy-settings.db")

	legacyDB, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open legacy db: %v", err)
	}

	if _, err := legacyDB.Exec(`
		CREATE TABLE settings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			enroll_disable_context INTEGER NOT NULL DEFAULT 0,
			traefik_dynamic_config TEXT,
			discord_webhook TEXT
		);
	`); err != nil {
		t.Fatalf("failed to create legacy settings table: %v", err)
	}

	if _, err := legacyDB.Exec(`
		INSERT INTO settings (id, enroll_disable_context, traefik_dynamic_config, discord_webhook)
		VALUES (1, 1, '/etc/traefik/dynamic.yml', 'https://discord.example/hook');
	`); err != nil {
		t.Fatalf("failed to seed legacy settings row: %v", err)
	}

	if err := legacyDB.Close(); err != nil {
		t.Fatalf("failed to close legacy db: %v", err)
	}

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer db.Close()

	rows, err := db.db.Query("PRAGMA table_info(settings)")
	if err != nil {
		t.Fatalf("failed to query settings schema: %v", err)
	}
	defer rows.Close()

	columnNames := make(map[string]struct{})
	for rows.Next() {
		var (
			cid      int
			name     string
			colType  string
			notNull  int
			defaultV sql.NullString
			pk       int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultV, &pk); err != nil {
			t.Fatalf("failed to scan settings schema row: %v", err)
		}
		columnNames[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("failed while reading settings schema rows: %v", err)
	}

	if len(columnNames) != 2 {
		t.Fatalf("expected exactly 2 settings columns after migration, got %d", len(columnNames))
	}
	if _, ok := columnNames["id"]; !ok {
		t.Fatal("expected settings.id column to exist")
	}
	if _, ok := columnNames["enroll_disable_context"]; !ok {
		t.Fatal("expected settings.enroll_disable_context column to exist")
	}
	if _, ok := columnNames["traefik_dynamic_config"]; ok {
		t.Fatal("legacy column traefik_dynamic_config should have been removed")
	}
	if _, ok := columnNames["discord_webhook"]; ok {
		t.Fatal("legacy column discord_webhook should have been removed")
	}

	settings, err := db.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings() failed: %v", err)
	}
	if !settings.EnrollDisableContext {
		t.Fatal("expected enroll_disable_context value to be preserved after migration")
	}
}
