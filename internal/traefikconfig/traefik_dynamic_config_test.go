package traefikconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"crowdsec-manager/internal/config"
)

func TestManagedHostFilePath(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{ConfigDir: filepath.Join("C:", "app", "config")}

	tests := []struct {
		name       string
		input      string
		wantSuffix string
	}{
		{
			name:       "file path maps into traefik directory",
			input:      "/etc/traefik/dynamic_config.yml",
			wantSuffix: filepath.Join("traefik", "dynamic_config.yml"),
		},
		{
			name:       "directory path maps to managed overlay file",
			input:      "/etc/traefik/rules",
			wantSuffix: filepath.Join("traefik", "rules", "crowdsec-manager.yml"),
		},
		{
			name:       "rules mount root maps to managed overlay file",
			input:      "/rules",
			wantSuffix: filepath.Join("traefik", "rules", "crowdsec-manager.yml"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ManagedHostFilePath(cfg, tt.input)
			if err != nil {
				t.Fatalf("ManagedHostFilePath returned error: %v", err)
			}
			if !strings.HasSuffix(got, tt.wantSuffix) {
				t.Fatalf("managed host path = %q, want suffix %q", got, tt.wantSuffix)
			}
		})
	}
}

func TestUpsertWhitelistEntryCreatesManagedStructure(t *testing.T) {
	t.Parallel()

	content, err := UpsertWhitelistEntry("", "192.168.1.10")
	if err != nil {
		t.Fatalf("UpsertWhitelistEntry returned error: %v", err)
	}

	expectedParts := []string{
		"http:",
		"middlewares:",
		ManagedWhitelistMiddlewareName + ":",
		"ipAllowList:",
		"sourceRange:",
		"- 192.168.1.10",
	}
	for _, part := range expectedParts {
		if !strings.Contains(content, part) {
			t.Fatalf("managed whitelist content missing %q:\n%s", part, content)
		}
	}
}

func TestRemoveWhitelistEntryRemovesOnlyRequestedValue(t *testing.T) {
	t.Parallel()

	input := `http:
  middlewares:
    crowdsec-manager-ip-whitelist:
      ipAllowList:
        sourceRange:
          - 10.0.0.1
          - 10.0.0.2
`

	output, removed, err := RemoveWhitelistEntry(input, "10.0.0.1")
	if err != nil {
		t.Fatalf("RemoveWhitelistEntry returned error: %v", err)
	}
	if !removed {
		t.Fatal("expected whitelist entry to be removed")
	}
	if strings.Contains(output, "- 10.0.0.1") {
		t.Fatalf("removed value still present:\n%s", output)
	}
	if !strings.Contains(output, "- 10.0.0.2") {
		t.Fatalf("other whitelist value missing:\n%s", output)
	}
}

func TestReadHostDirectoryCombinesYAMLDocuments(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	rulesDir := filepath.Join(root, "traefik", "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("failed to create rules directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "base.yml"), []byte("http:\n  routers: {}\n"), 0644); err != nil {
		t.Fatalf("failed to write base.yml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rulesDir, "crowdsec-manager.yml"), []byte("http:\n  middlewares: {}\n"), 0644); err != nil {
		t.Fatalf("failed to write crowdsec-manager.yml: %v", err)
	}

	cfg := &config.Config{ConfigDir: root}
	result, err := ReadHost(cfg, "/etc/traefik/rules")
	if err != nil {
		t.Fatalf("ReadHost returned error: %v", err)
	}

	if len(result.SourcePaths) != 2 {
		t.Fatalf("source paths = %d, want 2", len(result.SourcePaths))
	}
	if !strings.Contains(result.Content, "# Source: /etc/traefik/rules/base.yml") {
		t.Fatalf("combined content missing base source header:\n%s", result.Content)
	}
	if !strings.Contains(result.Content, "# Source: /etc/traefik/rules/crowdsec-manager.yml") {
		t.Fatalf("combined content missing managed source header:\n%s", result.Content)
	}
}
