package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/models"
)

func TestUpdateTraefikCaptchaConfigFileMode(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	traefikDir := filepath.Join(root, "traefik")
	if err := os.MkdirAll(traefikDir, 0755); err != nil {
		t.Fatalf("failed to create traefik directory: %v", err)
	}

	configPath := filepath.Join(traefikDir, "dynamic_config.yml")
	initialContent := "http:\n  middlewares:\n    existing:\n      headers: {}\n"
	if err := os.WriteFile(configPath, []byte(initialContent), 0644); err != nil {
		t.Fatalf("failed to write dynamic config: %v", err)
	}

	cfg := &config.Config{
		ConfigDir:              root,
		TraefikDynamicConfig:   "/etc/traefik/dynamic_config.yml",
		TraefikCaptchaHTMLPath: "/etc/traefik/conf/captcha.html",
		CaptchaGracePeriod:     1800,
	}
	req := models.CaptchaSetupRequest{
		Provider:  "turnstile",
		SiteKey:   "site-key",
		SecretKey: "secret-key",
	}

	if err := updateTraefikCaptchaConfig(cfg, req); err != nil {
		t.Fatalf("updateTraefikCaptchaConfig returned error: %v", err)
	}

	updatedContent, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("failed to read updated config: %v", err)
	}

	expectedParts := []string{
		"captchaProvider: turnstile",
		"captchaSiteKey: site-key",
		"captchaSecretKey: secret-key",
		"captchaHTMLFilePath: /etc/traefik/conf/captcha.html",
		"captchaGracePeriodSeconds: 1800",
	}
	for _, part := range expectedParts {
		if !strings.Contains(string(updatedContent), part) {
			t.Fatalf("updated config missing %q:\n%s", part, string(updatedContent))
		}
	}

	if _, err := os.Stat(configPath + ".bak"); err != nil {
		t.Fatalf("expected backup file to exist: %v", err)
	}
}

func TestUpdateTraefikCaptchaConfigDirectoryModeCreatesManagedOverlay(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	rulesDir := filepath.Join(root, "traefik", "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("failed to create rules directory: %v", err)
	}

	basePath := filepath.Join(rulesDir, "base.yml")
	baseContent := "http:\n  routers:\n    app:\n      rule: Host(`example.com`)\n"
	if err := os.WriteFile(basePath, []byte(baseContent), 0644); err != nil {
		t.Fatalf("failed to write base config: %v", err)
	}

	cfg := &config.Config{
		ConfigDir:              root,
		TraefikDynamicConfig:   "/etc/traefik/rules",
		TraefikCaptchaHTMLPath: "/etc/traefik/conf/captcha.html",
		CaptchaGracePeriod:     900,
	}
	req := models.CaptchaSetupRequest{
		Provider:  "hcaptcha",
		SiteKey:   "dir-site-key",
		SecretKey: "dir-secret-key",
	}

	if err := updateTraefikCaptchaConfig(cfg, req); err != nil {
		t.Fatalf("updateTraefikCaptchaConfig returned error: %v", err)
	}

	managedPath := filepath.Join(rulesDir, "crowdsec-manager.yml")
	managedContent, err := os.ReadFile(managedPath)
	if err != nil {
		t.Fatalf("failed to read managed overlay: %v", err)
	}

	expectedParts := []string{
		"captchaProvider: hcaptcha",
		"captchaSiteKey: dir-site-key",
		"captchaSecretKey: dir-secret-key",
		"captchaGracePeriodSeconds: 900",
	}
	for _, part := range expectedParts {
		if !strings.Contains(string(managedContent), part) {
			t.Fatalf("managed overlay missing %q:\n%s", part, string(managedContent))
		}
	}

	baseAfter, err := os.ReadFile(basePath)
	if err != nil {
		t.Fatalf("failed to read base config: %v", err)
	}
	if string(baseAfter) != baseContent {
		t.Fatalf("base config was modified unexpectedly:\n%s", string(baseAfter))
	}
}
