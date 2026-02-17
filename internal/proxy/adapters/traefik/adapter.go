package traefik

import (
	"context"
	"log/slog"

	"github.com/crowdsecurity/crowdsec-manager/internal/config"
	"github.com/crowdsecurity/crowdsec-manager/internal/docker"
	"github.com/crowdsecurity/crowdsec-manager/internal/proxy"
)

// TraefikAdapter implements proxy.ProxyAdapter for Traefik reverse proxy.
type TraefikAdapter struct {
	docker    *docker.Client
	cfg       *config.Config
	paths     config.ProxyPaths
	whitelist *WhitelistMgr
	captcha   *CaptchaMgr
	logs      *LogMgr
	bouncer   *BouncerMgr
}

// NewTraefikAdapter creates an uninitialized Traefik adapter.
func NewTraefikAdapter() *TraefikAdapter {
	return &TraefikAdapter{}
}

func (a *TraefikAdapter) Name() string             { return "Traefik" }
func (a *TraefikAdapter) Type() proxy.ProxyType    { return proxy.ProxyTraefik }

func (a *TraefikAdapter) SupportedFeatures() []proxy.Feature {
	return []proxy.Feature{
		proxy.FeatureWhitelist,
		proxy.FeatureCaptcha,
		proxy.FeatureLogs,
		proxy.FeatureBouncer,
		proxy.FeatureHealth,
	}
}

func (a *TraefikAdapter) Initialize(ctx context.Context, cfg proxy.InitConfig) error {
	a.docker = cfg.Docker
	a.cfg = cfg.Config
	a.paths = config.GetPaths("traefik")
	a.whitelist = &WhitelistMgr{docker: cfg.Docker, cfg: cfg.Config, paths: a.paths}
	a.captcha = &CaptchaMgr{docker: cfg.Docker, cfg: cfg.Config, paths: a.paths}
	a.logs = &LogMgr{docker: cfg.Docker, cfg: cfg.Config, paths: a.paths}
	a.bouncer = &BouncerMgr{docker: cfg.Docker, cfg: cfg.Config}
	slog.Info("traefik adapter initialized")
	return nil
}

func (a *TraefikAdapter) HealthCheck(ctx context.Context) (*proxy.HealthResult, error) {
	info, err := a.docker.InspectContainer(ctx, a.cfg.ProxyContainer)
	if err != nil {
		return &proxy.HealthResult{Healthy: false, Message: "traefik container not found: " + err.Error()}, nil
	}
	if info.State != "running" {
		return &proxy.HealthResult{Healthy: false, Message: "traefik container not running: " + info.State}, nil
	}
	return &proxy.HealthResult{Healthy: true, Message: "traefik is running"}, nil
}

func (a *TraefikAdapter) WhitelistManager() proxy.WhitelistManager { return a.whitelist }
func (a *TraefikAdapter) CaptchaManager() proxy.CaptchaManager     { return a.captcha }
func (a *TraefikAdapter) LogManager() proxy.LogManager              { return a.logs }
func (a *TraefikAdapter) BouncerManager() proxy.BouncerManager      { return a.bouncer }
