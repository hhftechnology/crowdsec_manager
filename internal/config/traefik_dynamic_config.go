package config

import (
	"fmt"
	"path"
	"strings"
)

const ManagedTraefikDynamicConfigFileName = "crowdsec-manager.yml"

type TraefikDynamicConfigMode string

const (
	TraefikDynamicConfigModeFile      TraefikDynamicConfigMode = "file"
	TraefikDynamicConfigModeDirectory TraefikDynamicConfigMode = "directory"
)

type TraefikDynamicConfigTarget struct {
	ConfiguredPath  string
	Mode            TraefikDynamicConfigMode
	ManagedFilePath string
}

func ResolveTraefikDynamicConfigTarget(configuredPath string) (TraefikDynamicConfigTarget, error) {
	trimmed := strings.TrimSpace(configuredPath)
	if trimmed == "" {
		return TraefikDynamicConfigTarget{}, fmt.Errorf("traefik dynamic config path is empty")
	}

	cleaned := path.Clean(trimmed)
	if cleaned == "." {
		return TraefikDynamicConfigTarget{}, fmt.Errorf("traefik dynamic config path is invalid: %q", configuredPath)
	}

	if isTraefikDynamicConfigFilePath(cleaned) {
		return TraefikDynamicConfigTarget{
			ConfiguredPath:  cleaned,
			Mode:            TraefikDynamicConfigModeFile,
			ManagedFilePath: cleaned,
		}, nil
	}

	return TraefikDynamicConfigTarget{
		ConfiguredPath:  cleaned,
		Mode:            TraefikDynamicConfigModeDirectory,
		ManagedFilePath: path.Join(cleaned, ManagedTraefikDynamicConfigFileName),
	}, nil
}

func isTraefikDynamicConfigFilePath(configuredPath string) bool {
	lower := strings.ToLower(configuredPath)
	return strings.HasSuffix(lower, ".yml") || strings.HasSuffix(lower, ".yaml")
}
