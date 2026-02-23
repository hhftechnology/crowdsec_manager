package handlers

import (
	"crowdsec-manager/internal/configvalidator"
	"crowdsec-manager/internal/logger"
)

// configValidator is the package-level validator used by handlers for auto-snapshotting.
// Set via SetConfigValidator during server startup.
var configValidator *configvalidator.Validator

// SetConfigValidator sets the package-level config validator for auto-snapshot hooks.
func SetConfigValidator(v *configvalidator.Validator) {
	configValidator = v
}

// autoSnapshot takes a snapshot of a config type after a successful write.
// Safe to call when configValidator is nil (no-op).
func autoSnapshot(configType string) {
	if configValidator == nil {
		return
	}
	if err := configValidator.SnapshotConfigByType(configType, "api"); err != nil {
		logger.Warn("Auto-snapshot failed", "type", configType, "error", err)
	}
}
