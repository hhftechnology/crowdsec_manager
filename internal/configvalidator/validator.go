package configvalidator

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/messaging"
	"crowdsec-manager/internal/models"
)

// configEntry defines a tracked config file
type configEntry struct {
	ConfigType    string
	FilePath      string
	ContainerName string
}

// Validator checks live config files against stored snapshots
type Validator struct {
	db     *database.Database
	docker *docker.Client
	hub    *messaging.Hub
	cfg    *config.Config
}

// NewValidator creates a config validator
func NewValidator(db *database.Database, dockerClient *docker.Client, hub *messaging.Hub, cfg *config.Config) *Validator {
	return &Validator{
		db:     db,
		docker: dockerClient,
		hub:    hub,
		cfg:    cfg,
	}
}

// trackedConfigs returns the list of config files to track
func (v *Validator) trackedConfigs() []configEntry {
	return []configEntry{
		{ConfigType: "acquis", FilePath: v.cfg.CrowdSecAcquisFile, ContainerName: v.cfg.CrowdsecContainerName},
		{ConfigType: "profiles", FilePath: v.cfg.CrowdSecProfilesPath, ContainerName: v.cfg.CrowdsecContainerName},
		{ConfigType: "whitelist", FilePath: v.cfg.CrowdSecWhitelistPath, ContainerName: v.cfg.CrowdsecContainerName},
		{ConfigType: "dynamic_config", FilePath: v.cfg.TraefikDynamicConfig, ContainerName: v.cfg.TraefikContainerName},
		{ConfigType: "static_config", FilePath: v.cfg.TraefikStaticConfig, ContainerName: v.cfg.TraefikContainerName},
	}
}

// readFileFromContainer reads a file's contents from inside a container
func (v *Validator) readFileFromContainer(containerName, filePath string) (string, error) {
	output, err := v.docker.ExecCommand(containerName, []string{"cat", filePath})
	if err != nil {
		return "", fmt.Errorf("failed to read %s from %s: %w", filePath, containerName, err)
	}
	return output, nil
}

// writeFileToContainer writes content to a file inside a container using tar copy
func (v *Validator) writeFileToContainer(containerName, filePath, content string) error {
	// Create a tar archive with the file
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Extract filename from path
	parts := strings.Split(filePath, "/")
	fileName := parts[len(parts)-1]

	hdr := &tar.Header{
		Name: fileName,
		Mode: 0644,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("failed to write tar header: %w", err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		return fmt.Errorf("failed to write tar content: %w", err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("failed to close tar writer: %w", err)
	}

	// Extract directory path
	dirPath := filePath[:strings.LastIndex(filePath, "/")]
	if dirPath == "" {
		dirPath = "/"
	}

	return v.docker.CopyToContainer(containerName, dirPath, &buf)
}

// hashContent returns SHA-256 hex digest of content
func hashContent(content string) string {
	h := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", h)
}

// SnapshotAll reads all live config files and saves them to DB
func (v *Validator) SnapshotAll() error {
	for _, entry := range v.trackedConfigs() {
		if err := v.SnapshotConfig(entry.ConfigType, entry.FilePath, entry.ContainerName, "auto"); err != nil {
			logger.Warn("Failed to snapshot config", "type", entry.ConfigType, "path", entry.FilePath, "error", err)
		}
	}
	return nil
}

// SnapshotConfig reads a single config file and saves it to DB
func (v *Validator) SnapshotConfig(configType, filePath, containerName, source string) error {
	content, err := v.readFileFromContainer(containerName, filePath)
	if err != nil {
		return err
	}

	snapshot := &models.ConfigSnapshot{
		ConfigType:  configType,
		FilePath:    filePath,
		Content:     content,
		ContentHash: hashContent(content),
		Source:      source,
	}

	return v.db.SaveConfigSnapshot(snapshot)
}

// SnapshotConfigByType snapshots a config by its type name, looking up path from tracked configs
func (v *Validator) SnapshotConfigByType(configType, source string) error {
	for _, entry := range v.trackedConfigs() {
		if entry.ConfigType == configType {
			return v.SnapshotConfig(entry.ConfigType, entry.FilePath, entry.ContainerName, source)
		}
	}
	return fmt.Errorf("unknown config type: %s", configType)
}

// ValidateAll checks all tracked configs against stored snapshots
func (v *Validator) ValidateAll() *models.ConfigValidationReport {
	report := &models.ConfigValidationReport{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Overall:   "ok",
	}

	for _, entry := range v.trackedConfigs() {
		result := v.validateConfig(entry)
		report.Results = append(report.Results, result)

		if result.Status == "drift" || result.Status == "missing" {
			report.Overall = "drift_detected"
		}
	}

	return report
}

// validateConfig checks a single config against its stored snapshot
func (v *Validator) validateConfig(entry configEntry) models.ConfigValidationResult {
	result := models.ConfigValidationResult{
		ConfigType: entry.ConfigType,
		FilePath:   entry.FilePath,
	}

	// Read live file from container
	liveContent, err := v.readFileFromContainer(entry.ContainerName, entry.FilePath)
	if err != nil {
		// File missing or container not running
		snapshot, dbErr := v.db.GetConfigSnapshot(entry.ConfigType, entry.FilePath)
		if dbErr != nil || snapshot == nil {
			result.Status = "no_snapshot"
			result.Message = fmt.Sprintf("File not accessible and no snapshot stored: %v", err)
			return result
		}

		result.Status = "missing"
		result.Message = fmt.Sprintf("File not accessible in container but snapshot exists: %v", err)
		result.DBHash = snapshot.ContentHash

		// Publish missing event
		v.hub.Broadcast(messaging.Event{
			Type:      "config_missing",
			Timestamp: time.Now(),
			Payload: map[string]string{
				"config_type": entry.ConfigType,
				"file_path":   entry.FilePath,
				"message":     result.Message,
			},
		})

		return result
	}

	liveHash := hashContent(liveContent)

	// Check against stored snapshot
	snapshot, err := v.db.GetConfigSnapshot(entry.ConfigType, entry.FilePath)
	if err != nil || snapshot == nil {
		result.Status = "no_snapshot"
		result.Message = "No snapshot stored yet"
		result.LiveHash = liveHash
		return result
	}

	result.DBHash = snapshot.ContentHash
	result.LiveHash = liveHash

	if liveHash == snapshot.ContentHash {
		result.Status = "match"
		result.Message = "Config matches stored snapshot"
	} else {
		result.Status = "drift"
		result.Message = "Config has changed since last snapshot"

		// Publish drift event
		v.hub.Broadcast(messaging.Event{
			Type:      "config_drift",
			Timestamp: time.Now(),
			Payload: map[string]string{
				"config_type": entry.ConfigType,
				"file_path":   entry.FilePath,
				"message":     result.Message,
			},
		})
	}

	return result
}

// RestoreConfig writes the stored snapshot content back to the container
func (v *Validator) RestoreConfig(configType string) error {
	var entry *configEntry
	for _, e := range v.trackedConfigs() {
		if e.ConfigType == configType {
			entry = &e
			break
		}
	}
	if entry == nil {
		return fmt.Errorf("unknown config type: %s", configType)
	}

	snapshot, err := v.db.GetConfigSnapshot(configType, entry.FilePath)
	if err != nil {
		return fmt.Errorf("failed to get snapshot: %w", err)
	}
	if snapshot == nil {
		return fmt.Errorf("no snapshot found for config type: %s", configType)
	}

	if err := v.writeFileToContainer(entry.ContainerName, entry.FilePath, snapshot.Content); err != nil {
		return fmt.Errorf("failed to restore config: %w", err)
	}

	// Publish restored event
	v.hub.Broadcast(messaging.Event{
		Type:      "config_restored",
		Timestamp: time.Now(),
		Payload: map[string]string{
			"config_type": configType,
			"file_path":   entry.FilePath,
			"message":     "Config restored from snapshot",
		},
	})

	logger.Info("Config restored from snapshot", "type", configType, "path", entry.FilePath)
	return nil
}

// GetSnapshots returns all stored config snapshots
func (v *Validator) GetSnapshots() ([]models.ConfigSnapshot, error) {
	return v.db.GetAllConfigSnapshots()
}

// DeleteSnapshot removes a snapshot for a config type
func (v *Validator) DeleteSnapshot(configType string) error {
	for _, entry := range v.trackedConfigs() {
		if entry.ConfigType == configType {
			return v.db.DeleteConfigSnapshot(configType, entry.FilePath)
		}
	}
	return fmt.Errorf("unknown config type: %s", configType)
}
