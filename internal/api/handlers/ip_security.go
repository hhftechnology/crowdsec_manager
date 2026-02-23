package handlers

import (
	"net"
	"strings"
)

// checkIPInCIDRList checks if an IP is in any CIDR range from the YAML content
func checkIPInCIDRList(ip, yamlContent string) bool {
	targetIP := net.ParseIP(ip)
	if targetIP == nil {
		return false
	}

	lines := strings.Split(yamlContent, "\n")
	inSourceRange := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.Contains(trimmed, "sourceRange:") {
			inSourceRange = true
			continue
		}

		if inSourceRange && strings.HasPrefix(trimmed, "- ") {
			cidr := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			cidr = strings.Trim(cidr, "\"'")

			if strings.Contains(cidr, "/") {
				_, ipNet, err := net.ParseCIDR(cidr)
				if err == nil && ipNet.Contains(targetIP) {
					return true
				}
			} else {
				if cidr == ip {
					return true
				}
			}
		} else if inSourceRange && !strings.HasPrefix(trimmed, "- ") && trimmed != "" {
			inSourceRange = false
		}
	}

	return false
}
