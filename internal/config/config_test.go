package config

import (
	"os"
	"testing"
)

func TestLoad_DefaultsIncludeGeoIPDBPath(t *testing.T) {
	// Use a temp dir to avoid creating ./logs/, ./backups/, ./config/ in CWD.
	dir := t.TempDir()
	t.Setenv("LOG_FILE", dir+"/test.log")
	t.Setenv("BACKUP_DIR", dir+"/backups")
	t.Setenv("CONFIG_DIR", dir+"/config")
	t.Setenv("DATABASE_PATH", dir+"/settings.db")
	t.Setenv("HISTORY_DATABASE_PATH", dir+"/history.db")
	t.Setenv("COMPOSE_FILE", dir+"/no-such-compose.yml")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GeoIPDBPath == "" {
		t.Fatalf("expected GeoIPDBPath to have a default; got empty")
	}
}

func TestLoad_GeoIPDBPathFromEnv(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("LOG_FILE", dir+"/test.log")
	t.Setenv("BACKUP_DIR", dir+"/backups")
	t.Setenv("CONFIG_DIR", dir+"/config")
	t.Setenv("DATABASE_PATH", dir+"/settings.db")
	t.Setenv("HISTORY_DATABASE_PATH", dir+"/history.db")
	t.Setenv("COMPOSE_FILE", dir+"/no-such-compose.yml")
	t.Setenv("GEOIP_DB_PATH", "/custom/path.mmdb")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.GeoIPDBPath != "/custom/path.mmdb" {
		t.Fatalf("GeoIPDBPath not honoured: %q", cfg.GeoIPDBPath)
	}
}

func TestEffectiveLimit(t *testing.T) {
	if got := EffectiveLimit(0, 100); got != 100 {
		t.Fatalf("0 should become max; got %d", got)
	}
	if got := EffectiveLimit(50, 100); got != 50 {
		t.Fatalf("50 should pass through; got %d", got)
	}
	if got := EffectiveLimit(500, 100); got != 100 {
		t.Fatalf("500 should clamp; got %d", got)
	}
}

func TestGetEnvHelpers(t *testing.T) {
	os.Unsetenv("UNIT_TEST_VAR")
	if got := getEnv("UNIT_TEST_VAR", "fallback"); got != "fallback" {
		t.Fatalf("getEnv default: %q", got)
	}
	t.Setenv("UNIT_TEST_VAR", "value")
	if got := getEnv("UNIT_TEST_VAR", "fallback"); got != "value" {
		t.Fatalf("getEnv hit: %q", got)
	}
	t.Setenv("UNIT_TEST_INT", "42")
	if got := getEnvAsInt("UNIT_TEST_INT", 0); got != 42 {
		t.Fatalf("getEnvAsInt hit: %d", got)
	}
	t.Setenv("UNIT_TEST_BOOL", "true")
	if !getEnvAsBool("UNIT_TEST_BOOL", false) {
		t.Fatal("getEnvAsBool hit")
	}
}
