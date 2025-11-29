package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"crowdsec-manager/internal/logger"
	"crowdsec-manager/internal/models"
)

// Manager handles backup operations
type Manager struct {
	backupDir     string
	retentionDays int
	backupItems   []string
}

// NewManager creates a new backup manager
func NewManager(backupDir string, retentionDays int) *Manager {
	return &Manager{
		backupDir:     backupDir,
		retentionDays: retentionDays,
		backupItems:   []string{"docker-compose.yml", "config"},
	}
}

// Create creates a new backup
func (m *Manager) Create(dryRun bool) (*models.Backup, error) {
	timestamp := time.Now().Format("20060102_150405")
	backupName := fmt.Sprintf("pangolin_backup_%s", timestamp)
	backupPath := filepath.Join(m.backupDir, backupName)
	archivePath := backupPath + ".tar.gz"

	logger.Info("Starting backup process", "name", backupName, "dryRun", dryRun)

	// Ensure backup directory exists
	if err := os.MkdirAll(m.backupDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create backup directory: %w", err)
	}

	if dryRun {
		logger.Info("DRY-RUN: Would create backup", "path", archivePath)
		return &models.Backup{
			ID:        backupName,
			Filename:  filepath.Base(archivePath),
			Path:      archivePath,
			CreatedAt: time.Now(),
		}, nil
	}

	// Create temporary directory for backup staging
	tempDir, err := os.MkdirTemp("", "crowdsec-backup-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Copy items to temp directory
	copiedItems := 0
	for _, item := range m.backupItems {
		sourcePath := filepath.Join(".", item)
		if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
			logger.Warn("Source path does not exist, skipping", "path", sourcePath, "item", item)
			continue
		}

		destPath := filepath.Join(tempDir, item)
		if err := m.copyPath(sourcePath, destPath); err != nil {
			logger.Warn("Failed to copy item, skipping", "item", item, "error", err)
			continue
		}
		logger.Info("Copied item", "item", item)
		copiedItems++
	}

	// Ensure at least one item was successfully copied
	if copiedItems == 0 {
		return nil, fmt.Errorf("no backup items were successfully copied")
	}

	// Create backup info file
	infoPath := filepath.Join(tempDir, "BACKUP_INFO.txt")
	infoContent := fmt.Sprintf(`Backup created: %s
Pangolin directory: %s
Items included:
%s
`, time.Now().Format(time.RFC3339), ".", strings.Join(m.backupItems, "\n"))

	if err := os.WriteFile(infoPath, []byte(infoContent), 0644); err != nil {
		return nil, fmt.Errorf("failed to write backup info: %w", err)
	}

	// Create tar.gz archive
	if err := m.createArchive(tempDir, archivePath); err != nil {
		return nil, fmt.Errorf("failed to create archive: %w", err)
	}

	// Get archive size
	info, err := os.Stat(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat archive: %w", err)
	}

	logger.Info("Backup created successfully", "path", archivePath, "size", info.Size())

	// Cleanup old backups
	if err := m.CleanupOld(); err != nil {
		logger.Warn("Failed to cleanup old backups", "error", err)
	}

	return &models.Backup{
		ID:        backupName,
		Filename:  filepath.Base(archivePath),
		Path:      archivePath,
		Size:      info.Size(),
		CreatedAt: time.Now(),
	}, nil
}

// List lists all available backups
func (m *Manager) List() ([]models.Backup, error) {
	pattern := filepath.Join(m.backupDir, "pangolin_backup_*.tar.gz")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to list backups: %w", err)
	}

	var backups []models.Backup
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			logger.Warn("Failed to stat backup file", "file", file, "error", err)
			continue
		}

		filename := filepath.Base(file)
		backupID := strings.TrimSuffix(filename, ".tar.gz")

		backups = append(backups, models.Backup{
			ID:        backupID,
			Filename:  filename,
			Path:      file,
			Size:      info.Size(),
			CreatedAt: info.ModTime(),
		})
	}

	// Sort by creation time (newest first)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].CreatedAt.After(backups[j].CreatedAt)
	})

	return backups, nil
}

// Delete deletes a backup by ID
func (m *Manager) Delete(backupID string) error {
	backupPath := filepath.Join(m.backupDir, backupID+".tar.gz")

	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup not found: %s", backupID)
	}

	if err := os.Remove(backupPath); err != nil {
		return fmt.Errorf("failed to delete backup: %w", err)
	}

	logger.Info("Backup deleted", "id", backupID)
	return nil
}

// Restore restores from a backup
func (m *Manager) Restore(backupID string) error {
	backupPath := filepath.Join(m.backupDir, backupID+".tar.gz")

	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup not found: %s", backupID)
	}

	logger.Info("Starting restore", "backup", backupID)

	// Create pre-restore backup
	timestamp := time.Now().Format("20060102_150405")
	preRestoreBackup := fmt.Sprintf("pre_restore_%s", timestamp)
	preRestorePath := filepath.Join(m.backupDir, preRestoreBackup)

	tempDir, err := os.MkdirTemp("", "crowdsec-restore-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// Backup current state
	for _, item := range m.backupItems {
		sourcePath := filepath.Join(".", item)
		if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
			continue
		}

		destPath := filepath.Join(preRestorePath, item)
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}

		if err := m.copyPath(sourcePath, destPath); err != nil {
			logger.Warn("Failed to backup current state", "item", item, "error", err)
		}
	}

	// Extract backup
	extractDir := filepath.Join(tempDir, "extract")
	if err := m.extractArchive(backupPath, extractDir); err != nil {
		return fmt.Errorf("failed to extract backup: %w", err)
	}

	// Find the extracted directory
	entries, err := os.ReadDir(extractDir)
	if err != nil {
		return fmt.Errorf("failed to read extracted directory: %w", err)
	}

	var extractedDir string
	for _, entry := range entries {
		if entry.IsDir() {
			extractedDir = filepath.Join(extractDir, entry.Name())
			break
		}
	}

	if extractedDir == "" {
		// Fallback: check if files are in root of extractDir
		extractedDir = extractDir
	}

	// Restore items
	for _, item := range m.backupItems {
		sourcePath := filepath.Join(extractedDir, item)
		if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
			logger.Warn("Item not found in backup", "item", item)
			continue
		}

		destPath := filepath.Join(".", item)

		// Remove existing item with retry
		if err := m.retryOperation(func() error {
			return os.RemoveAll(destPath)
		}, 3, time.Second); err != nil {
			return fmt.Errorf("failed to remove existing item %s: %w", item, err)
		}

		// Copy from backup with retry
		if err := m.retryOperation(func() error {
			return m.copyPath(sourcePath, destPath)
		}, 3, time.Second); err != nil {
			return fmt.Errorf("failed to restore item %s: %w", item, err)
		}

		logger.Info("Restored item", "item", item)
	}

	logger.Info("Restore completed successfully")
	return nil
}

// retryOperation retries an operation with exponential backoff
func (m *Manager) retryOperation(op func() error, attempts int, delay time.Duration) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = op(); err == nil {
			return nil
		}
		time.Sleep(delay)
		delay *= 2
	}
	return fmt.Errorf("operation failed after %d attempts: %w", attempts, err)
}

// CleanupOld removes backups older than retention period
func (m *Manager) CleanupOld() error {
	if m.retentionDays <= 0 {
		return nil
	}

	logger.Info("Checking for old backups to remove", "retentionDays", m.retentionDays)

	cutoffDate := time.Now().AddDate(0, 0, -m.retentionDays)
	pattern := filepath.Join(m.backupDir, "pangolin_backup_*.tar.gz")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to list backups: %w", err)
	}

	deletedCount := 0
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			logger.Warn("Failed to stat backup file", "file", file, "error", err)
			continue
		}

		if info.ModTime().Before(cutoffDate) {
			if err := os.Remove(file); err != nil {
				logger.Warn("Failed to remove old backup", "file", file, "error", err)
				continue
			}
			logger.Info("Removed old backup", "file", filepath.Base(file))
			deletedCount++
		}
	}

	if deletedCount > 0 {
		logger.Info("Cleaned up old backups", "count", deletedCount)
	} else {
		logger.Info("No old backups to remove")
	}

	return nil
}

// FindLatest finds the latest backup
func (m *Manager) FindLatest() (*models.Backup, error) {
	backups, err := m.List()
	if err != nil {
		return nil, err
	}

	if len(backups) == 0 {
		return nil, fmt.Errorf("no backups found")
	}

	return &backups[0], nil
}

// Helper methods

func (m *Manager) copyPath(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if srcInfo.IsDir() {
		return m.copyDir(src, dst)
	}
	return m.copyFile(src, dst)
}

func (m *Manager) copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	return os.Chmod(dst, srcInfo.Mode())
}

func (m *Manager) copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if err := m.copyPath(srcPath, dstPath); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) createArchive(sourceDir, archivePath string) error {
	archiveFile, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	defer archiveFile.Close()

	gzipWriter := gzip.NewWriter(archiveFile)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// Get the base name of the source directory to use as archive root
	baseName := filepath.Base(sourceDir)

	return filepath.Walk(sourceDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Create tar header from file info
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}

		// Calculate relative path from source directory
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}

		// Preserve the directory structure with base name as root
		if relPath == "." {
			header.Name = baseName
		} else {
			header.Name = filepath.ToSlash(filepath.Join(baseName, relPath))
		}

		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		// Copy file contents if it's a regular file
		if !info.IsDir() {
			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			if _, err := io.Copy(tarWriter, file); err != nil {
				return err
			}
		}

		return nil
	})
}

func (m *Manager) extractArchive(archivePath, destDir string) error {
	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer archiveFile.Close()

	gzipReader, err := gzip.NewReader(archiveFile)
	if err != nil {
		return err
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, header.Name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}

			file, err := os.Create(target)
			if err != nil {
				return err
			}

			if _, err := io.Copy(file, tarReader); err != nil {
				file.Close()
				return err
			}
			file.Close()

			if err := os.Chmod(target, os.FileMode(header.Mode)); err != nil {
				return err
			}
		}
	}

	return nil
}
