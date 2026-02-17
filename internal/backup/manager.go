package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec-manager/internal/config"
	"github.com/crowdsecurity/crowdsec-manager/internal/database"
	"github.com/crowdsecurity/crowdsec-manager/internal/docker"
)

// BackupInfo describes a backup archive.
type BackupInfo struct {
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	Size      int64  `json:"size"`
	Path      string `json:"-"`
}

// Manager handles backup creation, restoration, and cleanup.
type Manager struct {
	config *config.Config
	docker *docker.Client
	db     *database.Database
}

// NewManager creates a backup manager.
func NewManager(cfg *config.Config, dockerClient *docker.Client, db *database.Database) *Manager {
	return &Manager{
		config: cfg,
		docker: dockerClient,
		db:     db,
	}
}

func (m *Manager) backupDir() string {
	return filepath.Join(m.config.DataDir, "backups")
}

// Create generates a tar.gz backup containing the database and CrowdSec config.
func (m *Manager) Create(ctx context.Context) (*BackupInfo, error) {
	dir := m.backupDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create backup dir: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102-150405")
	name := fmt.Sprintf("backup-%s.tar.gz", timestamp)
	path := filepath.Join(dir, name)

	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create backup file: %w", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	// Back up the database file.
	dbPath := filepath.Join(m.config.DataDir, "crowdsec-manager.db")
	if err := addFileToTar(tw, dbPath, "crowdsec-manager.db"); err != nil {
		slog.Warn("failed to add database to backup", "error", err)
	}

	// Back up CrowdSec config from container.
	configFiles := []string{
		"/etc/crowdsec/config.yaml",
		"/etc/crowdsec/profiles.yaml",
		"/etc/crowdsec/acquis.yaml",
	}
	for _, cf := range configFiles {
		data, err := m.docker.ReadFileFromContainer(ctx, m.config.CrowdSecContainer, cf)
		if err != nil {
			slog.Warn("failed to read container file for backup", "file", cf, "error", err)
			continue
		}
		tarName := "crowdsec" + strings.ReplaceAll(cf, "/", "_")
		if err := addBytesToTar(tw, data, tarName); err != nil {
			slog.Warn("failed to add to backup", "file", cf, "error", err)
		}
	}

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat backup: %w", err)
	}

	return &BackupInfo{
		Name:      name,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Size:      info.Size(),
		Path:      path,
	}, nil
}

// Restore extracts a backup archive to the data directory.
func (m *Manager) Restore(_ context.Context, name string) error {
	path := filepath.Join(m.backupDir(), name)
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open backup %q: %w", name, err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	restoreDir := filepath.Join(m.config.DataDir, "restore")
	if err := os.MkdirAll(restoreDir, 0o755); err != nil {
		return fmt.Errorf("create restore dir: %w", err)
	}

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		target := filepath.Join(restoreDir, filepath.Base(hdr.Name))
		outFile, err := os.Create(target)
		if err != nil {
			return fmt.Errorf("create %q: %w", target, err)
		}
		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			return fmt.Errorf("extract %q: %w", target, err)
		}
		outFile.Close()
	}

	slog.Info("backup restored", "name", name, "restore_dir", restoreDir)
	return nil
}

// List returns all available backups sorted by creation time (newest first).
func (m *Manager) List() ([]BackupInfo, error) {
	dir := m.backupDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read backup dir: %w", err)
	}

	backups := make([]BackupInfo, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar.gz") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		backups = append(backups, BackupInfo{
			Name:      e.Name(),
			CreatedAt: info.ModTime().UTC().Format(time.RFC3339),
			Size:      info.Size(),
			Path:      filepath.Join(dir, e.Name()),
		})
	}

	sort.Slice(backups, func(i, j int) bool {
		return backups[i].CreatedAt > backups[j].CreatedAt
	})
	return backups, nil
}

// Delete removes a single backup by name.
func (m *Manager) Delete(name string) error {
	path := filepath.Join(m.backupDir(), name)
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete backup %q: %w", name, err)
	}
	return nil
}

// Cleanup removes the oldest backups beyond the retention count.
func (m *Manager) Cleanup(retention int) error {
	backups, err := m.List()
	if err != nil {
		return err
	}
	if len(backups) <= retention {
		return nil
	}

	for _, b := range backups[retention:] {
		if err := os.Remove(b.Path); err != nil {
			slog.Warn("failed to remove old backup", "name", b.Name, "error", err)
			continue
		}
		slog.Info("removed old backup", "name", b.Name)
	}
	return nil
}

func addFileToTar(tw *tar.Writer, filePath, tarName string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	hdr := &tar.Header{
		Name: tarName,
		Size: info.Size(),
		Mode: 0o644,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

func addBytesToTar(tw *tar.Writer, data []byte, tarName string) error {
	hdr := &tar.Header{
		Name: tarName,
		Size: int64(len(data)),
		Mode: 0o644,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
