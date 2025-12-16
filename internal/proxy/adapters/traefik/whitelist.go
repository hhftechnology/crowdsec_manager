package traefik

import (
	"context"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"fmt"
	"regexp"
	"strings"
)

// TraefikWhitelistManager implements WhitelistManager for Traefik
type TraefikWhitelistManager struct {
	dockerClient *docker.Client
	cfg          *config.Config
}

// NewTraefikWhitelistManager creates a new Traefik whitelist manager
func NewTraefikWhitelistManager(dockerClient *docker.Client, cfg *config.Config) *TraefikWhitelistManager {
	return &TraefikWhitelistManager{
		dockerClient: dockerClient,
		cfg:          cfg,
	}
}

// ViewWhitelist returns all whitelisted IPs from Traefik dynamic configuration
func (t *TraefikWhitelistManager) ViewWhitelist(ctx context.Context) ([]string, error) {
	logger.Info("Viewing Traefik whitelist")
	
	// Get Traefik whitelist from dynamic config
	traefikWL, err := t.dockerClient.ExecCommand(t.cfg.TraefikContainerName, []string{
		"cat", "/etc/traefik/dynamic_config.yml",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read Traefik dynamic config: %w", err)
	}
	
	return t.parseTraefikWhitelist(traefikWL), nil
}

// AddIP adds an IP address to the Traefik whitelist
func (t *TraefikWhitelistManager) AddIP(ctx context.Context, ip string) error {
	logger.Info("Adding IP to Traefik whitelist", "ip", ip)
	
	// Update Traefik dynamic config using sed to add IP to sourceRange
	_, err := t.dockerClient.ExecCommand(t.cfg.TraefikContainerName, []string{
		"sh", "-c", fmt.Sprintf(`sed -i '/sourceRange:/a\        - %s' /etc/traefik/dynamic_config.yml`, ip),
	})
	if err != nil {
		return fmt.Errorf("failed to add IP to Traefik whitelist: %w", err)
	}
	
	logger.Info("IP added to Traefik whitelist successfully", "ip", ip)
	return nil
}

// RemoveIP removes an IP address from the Traefik whitelist
func (t *TraefikWhitelistManager) RemoveIP(ctx context.Context, ip string) error {
	logger.Info("Removing IP from Traefik whitelist", "ip", ip)
	
	// Use sed to remove the specific IP from the dynamic config
	_, err := t.dockerClient.ExecCommand(t.cfg.TraefikContainerName, []string{
		"sh", "-c", fmt.Sprintf(`sed -i '/^\s*-\s*%s\s*$/d' /etc/traefik/dynamic_config.yml`, regexp.QuoteMeta(ip)),
	})
	if err != nil {
		return fmt.Errorf("failed to remove IP from Traefik whitelist: %w", err)
	}
	
	logger.Info("IP removed from Traefik whitelist successfully", "ip", ip)
	return nil
}

// AddCIDR adds a CIDR range to the Traefik whitelist
func (t *TraefikWhitelistManager) AddCIDR(ctx context.Context, cidr string) error {
	logger.Info("Adding CIDR to Traefik whitelist", "cidr", cidr)
	
	// Update Traefik dynamic config using sed to add CIDR to sourceRange
	_, err := t.dockerClient.ExecCommand(t.cfg.TraefikContainerName, []string{
		"sh", "-c", fmt.Sprintf(`sed -i '/sourceRange:/a\        - %s' /etc/traefik/dynamic_config.yml`, cidr),
	})
	if err != nil {
		return fmt.Errorf("failed to add CIDR to Traefik whitelist: %w", err)
	}
	
	logger.Info("CIDR added to Traefik whitelist successfully", "cidr", cidr)
	return nil
}

// RemoveCIDR removes a CIDR range from the Traefik whitelist
func (t *TraefikWhitelistManager) RemoveCIDR(ctx context.Context, cidr string) error {
	logger.Info("Removing CIDR from Traefik whitelist", "cidr", cidr)
	
	// Use sed to remove the specific CIDR from the dynamic config
	_, err := t.dockerClient.ExecCommand(t.cfg.TraefikContainerName, []string{
		"sh", "-c", fmt.Sprintf(`sed -i '/^\s*-\s*%s\s*$/d' /etc/traefik/dynamic_config.yml`, regexp.QuoteMeta(cidr)),
	})
	if err != nil {
		return fmt.Errorf("failed to remove CIDR from Traefik whitelist: %w", err)
	}
	
	logger.Info("CIDR removed from Traefik whitelist successfully", "cidr", cidr)
	return nil
}

// parseTraefikWhitelist parses Traefik whitelist configuration and extracts IPs/CIDRs
func (t *TraefikWhitelistManager) parseTraefikWhitelist(content string) []string {
	ips := []string{}
	lines := strings.Split(content, "\n")

	ipRegex := regexp.MustCompile(`^\s*-\s+([0-9\.\/]+)`)
	inSourceRange := false

	for _, line := range lines {
		if strings.Contains(line, "sourceRange:") {
			inSourceRange = true
			continue
		}

		if inSourceRange {
			if matches := ipRegex.FindStringSubmatch(line); len(matches) > 1 {
				ips = append(ips, matches[1])
			} else if !strings.HasPrefix(strings.TrimSpace(line), "-") {
				inSourceRange = false
			}
		}
	}

	return ips
}