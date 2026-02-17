package traefik

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/crowdsecurity/crowdsec-manager/internal/config"
	"github.com/crowdsecurity/crowdsec-manager/internal/docker"
	"github.com/crowdsecurity/crowdsec-manager/internal/proxy"
)

// BouncerMgr queries bouncer status via CrowdSec's cscli.
type BouncerMgr struct {
	docker *docker.Client
	cfg    *config.Config
}

// cscliBouncerEntry matches the JSON output of cscli bouncers list.
type cscliBouncerEntry struct {
	Name      string `json:"name"`
	IPAddress string `json:"ip_address"`
	Type      string `json:"type"`
	LastPull  string `json:"last_pull"`
	Valid     bool   `json:"is_valid"`
}

func (m *BouncerMgr) Status(ctx context.Context) (*proxy.BouncerStatus, error) {
	bouncers, err := m.List(ctx)
	if err != nil {
		return nil, err
	}
	return &proxy.BouncerStatus{
		Bouncers: bouncers,
		Count:    len(bouncers),
	}, nil
}

func (m *BouncerMgr) List(ctx context.Context) ([]proxy.BouncerInfo, error) {
	// SAFE: all arguments are string literals, no user input.
	output, err := m.docker.ExecInContainer(ctx, m.cfg.CrowdSecContainer, []string{
		"cscli", "bouncers", "list", "-o", "json",
	})
	if err != nil {
		return nil, fmt.Errorf("list bouncers: %w", err)
	}

	var raw []cscliBouncerEntry
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		return nil, fmt.Errorf("parse bouncer list: %w", err)
	}

	bouncers := make([]proxy.BouncerInfo, 0, len(raw))
	for _, b := range raw {
		bouncers = append(bouncers, proxy.BouncerInfo{
			Name:      b.Name,
			IPAddress: b.IPAddress,
			Type:      b.Type,
			LastPull:  b.LastPull,
			Valid:     b.Valid,
		})
	}
	return bouncers, nil
}
