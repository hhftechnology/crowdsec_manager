package config

import (
	"fmt"
	"os"
)

// Validate checks that the configuration is usable.
// It verifies the data directory exists (creating it if needed) and
// checks for the Docker socket.
func Validate(cfg *Config) error {
	if err := ensureDir(cfg.DataDir); err != nil {
		return fmt.Errorf("data directory %q: %w", cfg.DataDir, err)
	}

	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		return fmt.Errorf("docker socket not found at /var/run/docker.sock: %w", err)
	}

	return nil
}

func ensureDir(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return os.MkdirAll(path, 0o755)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists but is not a directory", path)
	}
	return nil
}
