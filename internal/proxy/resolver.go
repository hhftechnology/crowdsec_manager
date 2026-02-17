package proxy

import (
	"context"
	"log/slog"
	"strings"

	"github.com/crowdsecurity/crowdsec-manager/internal/docker"
)

// imagePatterns maps known container image substrings to proxy types.
var imagePatterns = map[string]ProxyType{
	"traefik":  ProxyTraefik,
	"nginx":    ProxyNginx,
	"caddy":    ProxyCaddy,
	"haproxy":  ProxyHAProxy,
	"zoraxy":   ProxyZoraxy,
}

// Resolve determines which proxy type to use. It checks the config override
// first, then inspects running Docker containers, and falls back to standalone.
func Resolve(ctx context.Context, configProxy string, dockerClient *docker.Client) ProxyType {
	// Honor explicit configuration.
	if configProxy != "" {
		pt := ProxyType(strings.ToLower(configProxy))
		if _, ok := Get(pt); ok {
			slog.Info("proxy type from config", "type", pt)
			return pt
		}
		slog.Warn("configured proxy type not registered, auto-detecting", "configured", configProxy)
	}

	// Auto-detect from running containers.
	containers, err := dockerClient.ListContainers(ctx)
	if err != nil {
		slog.Error("failed to list containers for proxy detection", "error", err)
		return ProxyStandalone
	}

	for _, ctr := range containers {
		imageLower := strings.ToLower(ctr.Image)
		for pattern, pt := range imagePatterns {
			if strings.Contains(imageLower, pattern) {
				if _, ok := Get(pt); ok {
					slog.Info("proxy type auto-detected", "type", pt, "container", ctr.Name)
					return pt
				}
			}
		}
	}

	slog.Info("no proxy detected, using standalone mode")
	return ProxyStandalone
}
