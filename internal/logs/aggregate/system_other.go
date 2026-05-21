//go:build !linux

package aggregate

import "crowdsec-manager/internal/models"

// PrimeSystemStats is a no-op on non-Linux platforms.
func PrimeSystemStats() {}

// GetSystemStats returns zero-value stats on platforms without /proc support.
func GetSystemStats() *models.SystemStats {
	return &models.SystemStats{}
}
