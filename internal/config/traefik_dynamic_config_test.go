package config

import "testing"

func TestResolveTraefikDynamicConfigTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		input             string
		wantMode          TraefikDynamicConfigMode
		wantConfigured    string
		wantManagedTarget string
		wantErr           bool
	}{
		{
			name:              "yaml file path stays file target",
			input:             "/etc/traefik/dynamic_config.yml",
			wantMode:          TraefikDynamicConfigModeFile,
			wantConfigured:    "/etc/traefik/dynamic_config.yml",
			wantManagedTarget: "/etc/traefik/dynamic_config.yml",
		},
		{
			name:              "yaml file path trims whitespace",
			input:             "  /etc/traefik/dynamic_config.yaml  ",
			wantMode:          TraefikDynamicConfigModeFile,
			wantConfigured:    "/etc/traefik/dynamic_config.yaml",
			wantManagedTarget: "/etc/traefik/dynamic_config.yaml",
		},
		{
			name:              "directory path resolves managed overlay file",
			input:             "/etc/traefik/rules",
			wantMode:          TraefikDynamicConfigModeDirectory,
			wantConfigured:    "/etc/traefik/rules",
			wantManagedTarget: "/etc/traefik/rules/crowdsec-manager.yml",
		},
		{
			name:              "directory path with trailing slash is normalized",
			input:             "/rules/",
			wantMode:          TraefikDynamicConfigModeDirectory,
			wantConfigured:    "/rules",
			wantManagedTarget: "/rules/crowdsec-manager.yml",
		},
		{
			name:    "empty path fails",
			input:   "   ",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			target, err := ResolveTraefikDynamicConfigTarget(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got target=%+v", target)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if target.Mode != tt.wantMode {
				t.Fatalf("mode = %q, want %q", target.Mode, tt.wantMode)
			}
			if target.ConfiguredPath != tt.wantConfigured {
				t.Fatalf("configured path = %q, want %q", target.ConfiguredPath, tt.wantConfigured)
			}
			if target.ManagedFilePath != tt.wantManagedTarget {
				t.Fatalf("managed file path = %q, want %q", target.ManagedFilePath, tt.wantManagedTarget)
			}
		})
	}
}
