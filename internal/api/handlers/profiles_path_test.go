package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/models"
)

func TestGetProfilesPathUsesCrowdSecConfigDir(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		ConfigDir:          filepath.Join("tmp", "config"),
		CrowdSecAcquisFile: filepath.Join("etc", "crowdsec", "acquis.yaml"),
	}

	got := getProfilesPath(cfg)
	want := filepath.Join("tmp", "config", "crowdsec", "profiles.yaml")
	if got != want {
		t.Fatalf("getProfilesPath() = %q, want %q", got, want)
	}
}

func TestUpdateProfilesWritesToCrowdSecConfigDir(t *testing.T) {
	configDir := t.TempDir()
	acquisDir := filepath.Join(t.TempDir(), "etc", "crowdsec")
	cfg := &config.Config{
		ConfigDir:             configDir,
		CrowdSecAcquisFile:    filepath.Join(acquisDir, "acquis.yaml"),
		CrowdsecContainerName: "crowdsec",
	}

	db, err := database.New(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close database: %v", err)
		}
	})

	content := "name: test_profile\nfilters:\n  - Alert.Remediation == true\n"
	body, err := json.Marshal(models.ProfileRequest{Content: content})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	r := newTestRouter()
	r.PUT("/profiles", UpdateProfiles(db, cfg, &docker.Client{}))
	req := httptest.NewRequest(http.MethodPut, "/profiles", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("UpdateProfiles status = %d, want %d; body: %s", w.Code, http.StatusOK, w.Body.String())
	}

	writtenPath := filepath.Join(configDir, "crowdsec", "profiles.yaml")
	written, err := os.ReadFile(writtenPath)
	if err != nil {
		t.Fatalf("read written profiles file: %v", err)
	}
	if string(written) != content {
		t.Fatalf("written profiles content = %q, want %q", string(written), content)
	}

	legacyPath := filepath.Join(acquisDir, "profiles.yaml")
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Fatalf("legacy profiles path stat error = %v, want not exist", err)
	}

	history, err := db.GetLatestProfileHistory()
	if err != nil {
		t.Fatalf("get latest profile history: %v", err)
	}
	if history == nil || history.Content != content {
		t.Fatalf("latest profile history = %#v, want content %q", history, content)
	}
}
