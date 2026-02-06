package api

import (
	"crowdsec-manager/internal/backup"
	"crowdsec-manager/internal/compose"
	"crowdsec-manager/internal/config"
	"crowdsec-manager/internal/cron"
	"crowdsec-manager/internal/database"
	"crowdsec-manager/internal/docker"
	"crowdsec-manager/internal/proxy"
)

// Dependencies holds all shared dependencies for API route handlers.
// This struct reduces parameter sprawl in route registration functions
// and makes it easy to add new dependencies without changing signatures.
type Dependencies struct {
	Docker         *docker.Client
	DB             *database.Database
	Config         *config.Config
	ProxyAdapter   proxy.ProxyAdapter
	ProxyManager   *proxy.ProxyManager
	BackupManager  *backup.Manager
	CronScheduler  *cron.Scheduler
	ComposeManager *compose.ComposeManager
}
