package traefik

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec-manager/internal/config"
	"github.com/crowdsecurity/crowdsec-manager/internal/docker"
	"github.com/crowdsecurity/crowdsec-manager/internal/proxy"
)

// LogMgr retrieves and parses Traefik access logs.
type LogMgr struct {
	docker *docker.Client
	cfg    *config.Config
	paths  config.ProxyPaths
}

func (m *LogMgr) GetLogs(ctx context.Context, opts proxy.LogOptions) ([]proxy.LogEntry, error) {
	lines := opts.Lines
	if lines <= 0 {
		lines = 100
	}

	service := opts.Service
	if service == "" {
		service = m.cfg.ProxyContainer
	}

	raw, err := m.docker.GetContainerLogs(ctx, service, lines)
	if err != nil {
		return nil, fmt.Errorf("get traefik logs: %w", err)
	}

	return parseLogLines(raw, "traefik"), nil
}

func (m *LogMgr) StreamLogs(ctx context.Context, opts proxy.LogOptions) (<-chan proxy.LogEntry, error) {
	service := opts.Service
	if service == "" {
		service = m.cfg.ProxyContainer
	}

	reader, err := m.docker.StreamContainerLogs(ctx, service)
	if err != nil {
		return nil, fmt.Errorf("stream traefik logs: %w", err)
	}

	ch := make(chan proxy.LogEntry, 64)
	go func() {
		defer close(ch)
		defer reader.Close()

		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
				line := scanner.Text()
				if line = strings.TrimSpace(line); line == "" {
					continue
				}
				ch <- proxy.LogEntry{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Level:     "info",
					Message:   line,
					Source:    "traefik",
				}
			}
		}
	}()

	return ch, nil
}

func parseLogLines(raw, source string) []proxy.LogEntry {
	lines := strings.Split(raw, "\n")
	entries := make([]proxy.LogEntry, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Clean up Docker log prefix bytes (first 8 bytes are stream header).
		if len(line) > 8 && (line[0] == 1 || line[0] == 2) {
			line = line[8:]
		}
		entries = append(entries, proxy.LogEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Level:     "info",
			Message:   line,
			Source:    source,
		})
	}
	return entries
}
