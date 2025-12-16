package e2e

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// MigrationTestSuite tests migration scenarios from legacy to multi-proxy
type MigrationTestSuite struct {
	env    *TestEnvironment
	client *http.Client
}

// NewMigrationTestSuite creates a new migration test suite
func NewMigrationTestSuite(env *TestEnvironment) *MigrationTestSuite {
	return &MigrationTestSuite{
		env: env,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// TestLegacyTraefikMigration tests migration from legacy Traefik installation
func TestLegacyTraefikMigration(t *testing.T) {
	env := SetupTestEnvironment(t, "traefik", "single")
	defer env.Cleanup()
	
	suite := NewMigrationTestSuite(env)
	suite.testLegacyTraefikMigration(t)
}

// testLegacyTraefikMigration tests complete legacy Traefik migration
func (m *MigrationTestSuite) testLegacyTraefikMigration(t *testing.T) {
	// Create legacy database with old schema
	if err := m.createLegacyDatabase(); err != nil {
		t.Fatalf("Failed to create legacy database: %v", err)
	}
	
	// Create legacy environment variables
	if err := m.createLegacyEnvironment(); err != nil {
		t.Fatalf("Failed to create legacy environment: %v", err)
	}
	
	// Start services with legacy configuration
	ctx := context.Background()
	if err := m.env.StartServices(ctx); err != nil {
		t.Fatalf("Failed to start services: %v", err)
	}
	defer m.env.StopServices(ctx)
	
	// Wait for services to be ready
	if err := m.env.WaitForServices(ctx, 2*time.Minute); err != nil {
		t.Fatalf("Services not ready: %v", err)
	}
	
	// Test that migration occurred automatically
	m.testAutomaticMigration(t)
	
	// Test that legacy functionality still works
	m.testLegacyFunctionality(t)
	
	// Test that new functionality is available
	m.testNewFunctionality(t)
	
	// Test database schema migration
	m.testDatabaseMigration(t)
}

// createLegacyDatabase creates a database with legacy schema
func (m *MigrationTestSuite) createLegacyDatabase() error {
	dbPath := filepath.Join(m.env.WorkDir, "data", "settings.db")
	
	// Ensure data directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return err
	}
	
	// Create database with legacy schema
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	
	// Create legacy settings table
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS settings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			traefik_container_name TEXT NOT NULL DEFAULT 'traefik',
			traefik_dynamic_config TEXT NOT NULL DEFAULT '/etc/traefik/dynamic_config.yml',
			traefik_static_config TEXT NOT NULL DEFAULT '/etc/traefik/traefik_config.yml',
			traefik_access_log TEXT NOT NULL DEFAULT '/var/log/traefik/access.log',
			crowdsec_container_name TEXT NOT NULL DEFAULT 'crowdsec',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		return err
	}
	
	// Insert legacy settings
	_, err = db.Exec(`
		INSERT INTO settings (
			traefik_container_name,
			traefik_dynamic_config,
			traefik_static_config,
			traefik_access_log,
			crowdsec_container_name
		) VALUES (?, ?, ?, ?, ?)
	`, "traefik", "/etc/traefik/dynamic_config.yml", "/etc/traefik/traefik_config.yml", 
		"/var/log/traefik/access.log", "crowdsec")
	
	return err
}

// createLegacyEnvironment creates legacy environment variables
func (m *MigrationTestSuite) createLegacyEnvironment() error {
	envPath := filepath.Join(m.env.WorkDir, ".env")
	
	legacyEnv := `# Legacy Traefik configuration
TRAEFIK_CONTAINER_NAME=traefik
TRAEFIK_DYNAMIC_CONFIG=/etc/traefik/dynamic_config.yml
TRAEFIK_STATIC_CONFIG=/etc/traefik/traefik_config.yml
TRAEFIK_ACCESS_LOG=/var/log/traefik/access.log
CROWDSEC_CONTAINER_NAME=crowdsec
COMPOSE_MODE=single
`
	
	return os.WriteFile(envPath, []byte(legacyEnv), 0644)
}

// testAutomaticMigration tests that migration occurred automatically
func (m *MigrationTestSuite) testAutomaticMigration(t *testing.T) {
	baseURL := m.env.GetServiceURL("crowdsec-manager")
	
	// Test that proxy type was detected as Traefik
	resp, err := m.client.Get(baseURL + "/api/proxy/current")
	if err != nil {
		t.Fatalf("Failed to call proxy current endpoint: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Proxy current endpoint returned status %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}
	
	var proxyInfo map[string]interface{}
	if err := json.Unmarshal(body, &proxyInfo); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}
	
	// Verify proxy type was auto-detected as Traefik
	if proxyType, ok := proxyInfo["type"].(string); !ok || proxyType != "traefik" {
		t.Errorf("Expected proxy type 'traefik', got %v", proxyInfo["type"])
	}
	
	// Verify migration flag is set
	if migrated, ok := proxyInfo["migrated"].(bool); !ok || !migrated {
		t.Error("Migration flag should be set to true")
	}
}

// testLegacyFunctionality tests that legacy functionality still works
func (m *MigrationTestSuite) testLegacyFunctionality(t *testing.T) {
	baseURL := m.env.GetServiceURL("crowdsec-manager")
	
	// Test legacy Traefik whitelist endpoint
	resp, err := m.client.Get(baseURL + "/api/traefik/whitelist")
	if err != nil {
		t.Errorf("Failed to call legacy whitelist endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Legacy whitelist endpoint returned status %d", resp.StatusCode)
		}
	}
	
	// Test legacy field names in API responses
	resp, err = m.client.Get(baseURL + "/api/proxy/current")
	if err != nil {
		t.Errorf("Failed to call proxy current endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err == nil {
			// Should have legacy field names
			if _, ok := data["traefik_enabled"]; !ok {
				t.Error("Legacy traefik_enabled field not found")
			}
			if _, ok := data["traefik_container_name"]; !ok {
				t.Error("Legacy traefik_container_name field not found")
			}
		}
	}
	
	// Test legacy environment variable mapping
	resp, err = m.client.Get(baseURL + "/api/configuration")
	if err != nil {
		t.Errorf("Failed to call configuration endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		
		var config map[string]interface{}
		if err := json.Unmarshal(body, &config); err == nil {
			// Should show that legacy variables were mapped
			if containerName, ok := config["container_name"].(string); !ok || containerName != "traefik" {
				t.Error("Legacy container name not properly mapped")
			}
		}
	}
}

// testNewFunctionality tests that new functionality is available
func (m *MigrationTestSuite) testNewFunctionality(t *testing.T) {
	baseURL := m.env.GetServiceURL("crowdsec-manager")
	
	// Test new generic proxy endpoints
	resp, err := m.client.Get(baseURL + "/api/proxy/types")
	if err != nil {
		t.Errorf("Failed to call proxy types endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Proxy types endpoint returned status %d", resp.StatusCode)
		}
	}
	
	// Test new proxy features endpoint
	resp, err = m.client.Get(baseURL + "/api/proxy/features")
	if err != nil {
		t.Errorf("Failed to call proxy features endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Proxy features endpoint returned status %d", resp.StatusCode)
		}
	}
	
	// Test new generic whitelist endpoint
	resp, err = m.client.Get(baseURL + "/api/whitelist")
	if err != nil {
		t.Errorf("Failed to call generic whitelist endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Generic whitelist endpoint returned status %d", resp.StatusCode)
		}
	}
	
	// Test that responses include both legacy and new fields
	resp, err = m.client.Get(baseURL + "/api/proxy/current")
	if err != nil {
		t.Errorf("Failed to call proxy current endpoint: %v", err)
	} else {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		
		var data map[string]interface{}
		if err := json.Unmarshal(body, &data); err == nil {
			// Should have both legacy and new fields
			if _, ok := data["traefik_enabled"]; !ok {
				t.Error("Legacy traefik_enabled field not found")
			}
			if _, ok := data["proxy_enabled"]; !ok {
				t.Error("New proxy_enabled field not found")
			}
			if _, ok := data["proxy_type"]; !ok {
				t.Error("New proxy_type field not found")
			}
		}
	}
}

// testDatabaseMigration tests that database schema was migrated correctly
func (m *MigrationTestSuite) testDatabaseMigration(t *testing.T) {
	dbPath := filepath.Join(m.env.WorkDir, "data", "settings.db")
	
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()
	
	// Check that new proxy_settings table exists
	var tableName string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='proxy_settings'").Scan(&tableName)
	if err != nil {
		t.Errorf("proxy_settings table not found: %v", err)
	}
	
	// Check that settings table has new columns
	rows, err := db.Query("PRAGMA table_info(settings)")
	if err != nil {
		t.Fatalf("Failed to get table info: %v", err)
	}
	defer rows.Close()
	
	columns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, pk int
		var defaultValue sql.NullString
		
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
			continue
		}
		columns[name] = true
	}
	
	// Check for new columns
	expectedColumns := []string{"proxy_type", "proxy_enabled", "compose_mode"}
	for _, col := range expectedColumns {
		if !columns[col] {
			t.Errorf("New column %s not found in settings table", col)
		}
	}
	
	// Check that proxy_settings was populated
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM proxy_settings").Scan(&count)
	if err != nil {
		t.Errorf("Failed to count proxy_settings: %v", err)
	} else if count == 0 {
		t.Error("proxy_settings table is empty - migration may have failed")
	}
	
	// Verify proxy_settings content
	var proxyType, containerName string
	err = db.QueryRow("SELECT proxy_type, container_name FROM proxy_settings WHERE id = 1").Scan(&proxyType, &containerName)
	if err != nil {
		t.Errorf("Failed to read proxy_settings: %v", err)
	} else {
		if proxyType != "traefik" {
			t.Errorf("Expected proxy_type 'traefik', got %s", proxyType)
		}
		if containerName != "traefik" {
			t.Errorf("Expected container_name 'traefik', got %s", containerName)
		}
	}
}

// TestEnvironmentVariableMigration tests migration of environment variables
func TestEnvironmentVariableMigration(t *testing.T) {
	testCases := []struct {
		name        string
		legacyVars  map[string]string
		expectedType string
	}{
		{
			name: "Traefik_Legacy_Vars",
			legacyVars: map[string]string{
				"TRAEFIK_CONTAINER_NAME": "my-traefik",
				"TRAEFIK_DYNAMIC_CONFIG": "/custom/dynamic.yml",
			},
			expectedType: "traefik",
		},
		{
			name: "No_Legacy_Vars",
			legacyVars: map[string]string{
				"PROXY_TYPE": "nginx",
			},
			expectedType: "nginx",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			env := SetupTestEnvironment(t, tc.expectedType, "single")
			defer env.Cleanup()
			
			// Create environment file with test variables
			envContent := ""
			for key, value := range tc.legacyVars {
				envContent += fmt.Sprintf("%s=%s\n", key, value)
			}
			
			envPath := filepath.Join(env.WorkDir, ".env")
			if err := os.WriteFile(envPath, []byte(envContent), 0644); err != nil {
				t.Fatalf("Failed to create env file: %v", err)
			}
			
			suite := NewMigrationTestSuite(env)
			
			// Start services
			ctx := context.Background()
			if err := env.StartServices(ctx); err != nil {
				t.Fatalf("Failed to start services: %v", err)
			}
			defer env.StopServices(ctx)
			
			if err := env.WaitForServices(ctx, 2*time.Minute); err != nil {
				t.Fatalf("Services not ready: %v", err)
			}
			
			// Test that proxy type was detected correctly
			baseURL := env.GetServiceURL("crowdsec-manager")
			resp, err := suite.client.Get(baseURL + "/api/proxy/current")
			if err != nil {
				t.Fatalf("Failed to call proxy current endpoint: %v", err)
			}
			defer resp.Body.Close()
			
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("Failed to read response: %v", err)
			}
			
			var proxyInfo map[string]interface{}
			if err := json.Unmarshal(body, &proxyInfo); err != nil {
				t.Fatalf("Failed to parse response: %v", err)
			}
			
			if proxyType, ok := proxyInfo["type"].(string); !ok || proxyType != tc.expectedType {
				t.Errorf("Expected proxy type %s, got %v", tc.expectedType, proxyInfo["type"])
			}
		})
	}
}

// TestConfigurationBackup tests that configuration is backed up during migration
func TestConfigurationBackup(t *testing.T) {
	env := SetupTestEnvironment(t, "traefik", "single")
	defer env.Cleanup()
	
	suite := NewMigrationTestSuite(env)
	
	// Create legacy database
	if err := suite.createLegacyDatabase(); err != nil {
		t.Fatalf("Failed to create legacy database: %v", err)
	}
	
	// Start services
	ctx := context.Background()
	if err := env.StartServices(ctx); err != nil {
		t.Fatalf("Failed to start services: %v", err)
	}
	defer env.StopServices(ctx)
	
	if err := env.WaitForServices(ctx, 2*time.Minute); err != nil {
		t.Fatalf("Services not ready: %v", err)
	}
	
	// Check that backup was created
	backupDir := filepath.Join(env.WorkDir, "backups")
	if _, err := os.Stat(backupDir); os.IsNotExist(err) {
		t.Error("Backup directory not created during migration")
	} else {
		// Check for backup files
		files, err := os.ReadDir(backupDir)
		if err != nil {
			t.Errorf("Failed to read backup directory: %v", err)
		} else if len(files) == 0 {
			t.Error("No backup files created during migration")
		}
	}
}