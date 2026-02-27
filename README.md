<div align="center">
  <h1><a href="https://github.com/hhftechnology/crowdsec_manager">CrowdSec Manager</a></h1>

[![Docker](https://img.shields.io/docker/pulls/hhftechnology/crowdsec-manager?style=flat-square)](https://hub.docker.com/r/hhftechnology/crowdsec-manager)
![Stars](https://img.shields.io/github/stars/hhftechnology/crowdsec_manager?style=flat-square)
[![Discord](https://img.shields.io/discord/994247717368909884?logo=discord&style=flat-square)](https://discord.gg/HDCt9MjyMJ)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8.svg)
![React Version](https://img.shields.io/badge/react-18.3-61DAFB.svg)
![Status](https://img.shields.io/badge/status-stable-22c55e.svg)
</div>

CrowdSec Manager is a web-based management interface for CrowdSec operations, Traefik integration, decisions, scenarios, backups, and logs.

## Stable release

- Current baseline: `1.0.0`
- Multi-proxy support: not available in this release

## Images

<img width="1200" height="630" alt="Dashboard" src="/images/dashboard-overview-countries-systems.jpeg"/>
<img width="1200" height="630" alt="Health & Diagnostics" src="/images/health-diagnostics-overview.jpeg"/>
<img width="1200" height="630" alt="Whitelist Management" src="/images/whitelist-management.jpeg"/>
<img width="1200" height="630" alt="IP Management" src="/images/ip-management.jpeg"/>
<img width="1200" height="630" alt="CrowdSec Allowlist Management" src="/images/allowlists-management.jpeg"/>
<img width="1200" height="630" alt="Scenario Management" src="/images/scenarios-management.jpeg"/>
<img width="1200" height="630" alt="Captcha Setup" src="/images/captcha-protection-detect.jpeg"/>
<img width="1200" height="630" alt="Decision List Analysis" src="/images/decisions-analysis-overview.jpeg"/>
<img width="1200" height="630" alt="Alert List Analysis" src="/images/alerts-analysis-overview.jpeg"/>
<img width="1200" height="630" alt="Logs Viewer" src="/images/logs-service-logs.jpeg"/>
<img width="1200" height="630" alt="Backup Management" src="/images/backup-management.jpeg"/>
<img width="1200" height="630" alt="System Update" src="/images/system-update.jpeg"/>
<img width="1200" height="630" alt="Services Management" src="/images/services-management.jpeg"/>
<img width="1200" height="630" alt="Configuration" src="/images/configuration-settings.jpeg"/>

### Image Index

| Screenshot File | Page |
| --- | --- |
| `alerts-analysis-filters.jpeg` | Alerts Analysis (filters panel) |
| `alerts-analysis-inspect-modal.jpeg` | Alerts Analysis (inspect modal) |
| `alerts-analysis-overview.jpeg` | Alerts Analysis (overview charts) |
| `alerts-analysis-results-table.jpeg` | Alerts Analysis (results table) |
| `allowlists-management.jpeg` | Allowlists Management |
| `backup-management.jpeg` | Backup Management |
| `bouncers-management.jpeg` | Bouncers Management |
| `captcha-protection-detect.jpeg` | Captcha Protection (detect) |
| `config-validation.jpeg` | Config Validation |
| `configuration-settings.jpeg` | Configuration Settings |
| `crowdsec-health-overview.jpeg` | CrowdSec Health Overview |
| `dashboard-overview-countries-systems.jpeg` | Dashboard (countries and systems) |
| `dashboard-overview-scenarios-blocked-ips.jpeg` | Dashboard (scenarios and blocked IPs) |
| `decisions-analysis-overview.jpeg` | Decisions Analysis (overview) |
| `decisions-results-table.jpeg` | Decisions Analysis (results table) |
| `health-diagnostics-overview.jpeg` | Health and Diagnostics |
| `hub-appsec-configurations.jpeg` | Hub Browser (AppSec configurations) |
| `hub-appsec-rules.jpeg` | Hub Browser (AppSec rules) |
| `hub-collections.jpeg` | Hub Browser (collections) |
| `hub-home-categories.jpeg` | Hub Browser (home categories) |
| `hub-log-parsers.jpeg` | Hub Browser (log parsers) |
| `hub-postoverflows.jpeg` | Hub Browser (postoverflows) |
| `hub-remediation-components.jpeg` | Hub Browser (remediation components) |
| `hub-scenarios-install-mode.jpeg` | Hub Browser (scenarios install mode) |
| `ip-management.jpeg` | IP Management |
| `logs-service-logs.jpeg` | Logs (service logs) |
| `notifications-detect.jpeg` | Notifications (detect) |
| `scenarios-management.jpeg` | Scenarios Management |
| `services-management.jpeg` | Services Management |
| `system-update.jpeg` | System Update |
| `terminal-container-shell.png` | Terminal (container shell) |
| `whitelist-management.jpeg` | Whitelist Management |

## Minimum Docker Compose

```yaml
services:
  crowdsec-manager:
    image: hhftechnology/crowdsec-manager:v1.0.0
    container_name: crowdsec-manager
    restart: unless-stopped
    expose:
      - "8080"
    environment:
      # Core Configuration
      - PORT=8080
      - ENVIRONMENT=production
      - TRAEFIK_DYNAMIC_CONFIG=/etc/traefik/dynamic_config.yml
      - TRAEFIK_CONTAINER_NAME=traefik
      - TRAEFIK_STATIC_CONFIG=/etc/traefik/traefik_config.yml
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /root/config:/app/config
      - /root/docker-compose.yml:/app/docker-compose.yml
      - ./backups:/app/backups
      - ./data:/app/data
    networks:
      - pangolin

networks:
  pangolin:
    external: true
```

## Run

```bash
mkdir -p ./backups ./data
docker network create pangolin
docker compose up -d
```

## Verify

```bash
curl http://localhost:8080/health
```

## API Endpoints

Base prefix: `/api`

### Health
- `GET /api/health/stack`
- `GET /api/health/crowdsec`
- `GET /api/health/complete`

### IP
- `GET /api/ip/public`
- `GET /api/ip/blocked/:ip`
- `GET /api/ip/security/:ip`
- `POST /api/ip/unban`

### Whitelist
- `GET /api/whitelist/view`
- `POST /api/whitelist/current`
- `POST /api/whitelist/manual`
- `POST /api/whitelist/cidr`
- `POST /api/whitelist/crowdsec`
- `POST /api/whitelist/traefik`
- `POST /api/whitelist/comprehensive`
- `DELETE /api/whitelist/remove`

### Allowlist
- `GET /api/allowlist/list`
- `POST /api/allowlist/create`
- `GET /api/allowlist/inspect/:name`
- `POST /api/allowlist/add`
- `POST /api/allowlist/remove`
- `DELETE /api/allowlist/:name`

### Scenarios
- `POST /api/scenarios/setup`
- `GET /api/scenarios/list`
- `GET /api/scenarios/files`
- `DELETE /api/scenarios/file`

### Captcha
- `POST /api/captcha/setup`
- `GET /api/captcha/status`
- `GET /api/captcha/detect`
- `POST /api/captcha/config`
- `POST /api/captcha/apply`

### Logs
- `GET /api/logs/crowdsec`
- `GET /api/logs/traefik`
- `GET /api/logs/traefik/advanced`
- `GET /api/logs/:service`
- `GET /api/logs/stream/:service`
- `GET /api/logs/structured/:service`

### Backup
- `GET /api/backup/list`
- `POST /api/backup/create`
- `POST /api/backup/restore`
- `DELETE /api/backup/:id`
- `POST /api/backup/cleanup`
- `GET /api/backup/latest`

### Update
- `GET /api/update/check`
- `POST /api/update/with-crowdsec`
- `POST /api/update/without-crowdsec`

### Services
- `GET /api/services/verify`
- `POST /api/services/shutdown`
- `POST /api/services/action`

### CrowdSec
- `GET /api/crowdsec/bouncers`
- `POST /api/crowdsec/bouncers`
- `DELETE /api/crowdsec/bouncers/:name`
- `GET /api/crowdsec/decisions`
- `POST /api/crowdsec/decisions`
- `DELETE /api/crowdsec/decisions`
- `POST /api/crowdsec/decisions/import`
- `GET /api/crowdsec/decisions/analysis`
- `GET /api/crowdsec/alerts/analysis`
- `GET /api/crowdsec/alerts/:id`
- `DELETE /api/crowdsec/alerts/:id`
- `GET /api/crowdsec/metrics`
- `POST /api/crowdsec/enroll`
- `POST /api/crowdsec/enroll/finalize`
- `GET /api/crowdsec/enroll/preferences`
- `PUT /api/crowdsec/enroll/preferences`
- `GET /api/crowdsec/status`

### Traefik
- `GET /api/traefik/config`
- `GET /api/traefik/config-path`
- `POST /api/traefik/config-path`

### Config
- `GET /api/config/settings`
- `PUT /api/config/settings`
- `GET /api/config/files/:container/:fileType`

### Notifications
- `GET /api/notifications/discord`
- `POST /api/notifications/discord`
- `GET /api/notifications/discord/preview`
- `GET /api/notifications/discord/detect`
- `POST /api/notifications/discord/config`
- `POST /api/notifications/discord/apply`

### Cron
- `POST /api/cron/setup`
- `GET /api/cron/list`
- `DELETE /api/cron/:id`

### Profiles
- `GET /api/profiles`
- `POST /api/profiles`

### Hosts
- `GET /api/hosts/list`

### Terminal
- `GET /api/terminal/:container`

### Config Validation
- `GET /api/config/validation/validate`
- `GET /api/config/validation/snapshots`
- `POST /api/config/validation/snapshot`
- `POST /api/config/validation/restore/:type`
- `POST /api/config/validation/accept/:type`
- `DELETE /api/config/validation/snapshot/:type`

### Hub
- `GET /api/hub/list`
- `POST /api/hub/upgrade`
- `GET /api/hub/categories`
- `GET /api/hub/:category/items`
- `POST /api/hub/:category/install`
- `POST /api/hub/:category/remove`
- `POST /api/hub/:category/manual-apply`
- `GET /api/hub/preferences`
- `GET /api/hub/preferences/:category`
- `PUT /api/hub/preferences/:category`
- `GET /api/hub/history`
- `GET /api/hub/history/:id`

### Simulation
- `GET /api/simulation/status`
- `POST /api/simulation/toggle`

### Events
- `GET /api/events/ws`
- `GET /api/events/sse`

## Documentation

For installation details, feature guides, and API reference, use the docs in [`docs`](https://crowdsec-manager.hhf.technology).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/hhftechnology/crowdsec_manager/issues)
- **Discussions**: [GitHub Discussions](https://github.com/hhftechnology/crowdsec_manager/discussions)

## Acknowledgments

- Original bash script by hhf-technology
- CrowdSec for the security engine
- Traefik for reverse proxy
- Shadcn/ui for UI components

---

**Built with ❤️ for the CrowdSec/Pangolin community**
