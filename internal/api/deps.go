package api

import (
	"github.com/crowdsecurity/crowdsec-manager/internal/backup"
	"github.com/crowdsecurity/crowdsec-manager/internal/config"
	"github.com/crowdsecurity/crowdsec-manager/internal/database"
	"github.com/crowdsecurity/crowdsec-manager/internal/docker"
	"github.com/crowdsecurity/crowdsec-manager/internal/proxy"
)

// Dependencies holds all shared resources available to API handlers.
type Dependencies struct {
	Docker        *docker.Client
	DB            *database.Database
	Config        *config.Config
	ProxyManager  *proxy.Manager
	BackupManager *backup.Manager
}
