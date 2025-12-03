# API Documentation

This document lists the available API endpoints in the CrowdSec Manager application.

## Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health/stack` | Checks the health of the Docker stack. |
| `GET` | `/api/health/crowdsec` | Checks the health of the CrowdSec service (LAPI connection, metrics). |
| `GET` | `/api/health/complete` | Runs complete diagnostics including database and configuration checks. |

## IP Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/ip/public` | Retrieves the server's public IP address. |
| `GET` | `/api/ip/blocked/:ip` | Checks if a specific IP is blocked by CrowdSec. |
| `POST` | `/api/ip/unban` | Unbans an IP address. Body: `{"ip": "x.x.x.x"}`. |

## CrowdSec

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/services/crowdsec/bouncers` | Lists all registered bouncers. |
| `POST` | `/api/services/crowdsec/bouncers` | Adds a new bouncer. Body: `{"name": "bouncer-name"}`. |
| `DELETE` | `/api/services/crowdsec/bouncers/:name` | Deletes a bouncer by name. |
| `GET` | `/api/services/crowdsec/decisions` | Lists active decisions (bans). |
| `GET` | `/api/services/crowdsec/decisions/analysis` | Advanced decision analysis with filters. Supports query params: `since`, `until`, `type`, `scope`, `origin`, `value`, `scenario`, `ip`, `range`, `includeAll`. |
| `GET` | `/api/services/crowdsec/alerts/analysis` | Advanced alert analysis with filters. Supports query params: `since`, `until`, `ip`, `range`, `scope`, `value`, `scenario`, `type`, `origin`, `includeAll`. |
| `GET` | `/api/services/crowdsec/metrics` | Retrieves CrowdSec metrics. |
| `POST` | `/api/services/crowdsec/enroll` | Enrolls the instance in the CrowdSec Console. Body: `{"enrollment_key": "key", "name": "optional-name"}`. |
| `GET` | `/api/services/crowdsec/status` | Checks CrowdSec Console enrollment status. |

## Services Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/services/verify` | Verifies the status of all managed services. |
| `POST` | `/api/services/shutdown` | Gracefully shuts down the stack. |
| `POST` | `/api/services/action` | Performs an action (start/stop/restart) on a service. Body: `{"service": "name", "action": "start|stop|restart"}`. |

## Whitelist

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/whitelist/view` | Views the current whitelist configuration. |
| `POST` | `/api/whitelist/current` | Whitelists the requestor's current IP. |
| `POST` | `/api/whitelist/manual` | Whitelists a manually provided IP. Body: `{"ip": "x.x.x.x"}`. |
| `POST` | `/api/whitelist/cidr` | Whitelists a CIDR range. Body: `{"cidr": "x.x.x.x/xx"}`. |
| `POST` | `/api/whitelist/crowdsec` | Adds IP to CrowdSec whitelist. |
| `POST` | `/api/whitelist/traefik` | Adds IP to Traefik whitelist. |
| `POST` | `/api/whitelist/comprehensive` | Sets up comprehensive whitelisting across services. |

## Scenarios

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/scenarios/setup` | Sets up custom scenarios. |
| `GET` | `/api/scenarios/list` | Lists installed scenarios. |
| `GET` | `/api/scenarios/files` | Lists scenario files. |
| `DELETE` | `/api/scenarios/file` | Deletes a scenario file. |

## Captcha

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/captcha/setup` | Sets up Captcha. |
| `GET` | `/api/captcha/status` | Checks Captcha status. |

## Logs

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/logs/crowdsec` | Retrieves CrowdSec logs. |
| `GET` | `/api/logs/traefik` | Retrieves Traefik logs. |
| `GET` | `/api/logs/traefik/advanced` | Advanced Traefik log analysis. |
| `GET` | `/api/logs/:service` | Retrieves logs for a specific service. |
| `GET` | `/api/logs/stream/:service` | Streams logs for a specific service (WebSocket). |

## Backups

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/backup/list` | Lists available backups. |
| `POST` | `/api/backup/create` | Creates a new backup. |
| `POST` | `/api/backup/restore` | Restores a backup. Body: `{"id": "backup-id"}`. |
| `DELETE` | `/api/backup/:id` | Deletes a backup. |
| `POST` | `/api/backup/cleanup` | Cleans up old backups. |
| `GET` | `/api/backup/latest` | Retrieves the latest backup. |

## Updates

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/update/check` | Checks for available updates. |
| `POST` | `/api/update/with-crowdsec` | Updates stack including CrowdSec. |
| `POST` | `/api/update/without-crowdsec` | Updates stack excluding CrowdSec. |

## Cron Jobs

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/cron/setup` | Sets up a cron job. |
| `GET` | `/api/cron/list` | Lists active cron jobs. |
| `DELETE` | `/api/cron/:id` | Deletes a cron job. |

## Allowlist (CrowdSec)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/allowlist/list` | Lists allowlists. |
| `POST` | `/api/allowlist/create` | Creates an allowlist. |
| `GET` | `/api/allowlist/inspect/:name` | Inspects a specific allowlist. |
| `POST` | `/api/allowlist/add` | Adds entries to an allowlist. |
| `POST` | `/api/allowlist/remove` | Removes entries from an allowlist. |
| `DELETE` | `/api/allowlist/:name` | Deletes an allowlist. |

## Traefik

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/services/traefik/config` | Retrieves Traefik configuration. |
| `GET` | `/api/services/traefik/config-path` | Gets the Traefik config path. |
| `POST` | `/api/services/traefik/config-path` | Sets the Traefik config path. |

## Configuration

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/services/config/settings` | Retrieves application settings. |
| `PUT` | `/api/services/config/settings` | Updates application settings. |
| `GET` | `/api/services/config/files/:container/:fileType` | Retrieves content of specific config files. |

## Notifications

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/notifications/discord` | Retrieves Discord notification configuration. |
| `POST` | `/api/notifications/discord` | Updates Discord notification configuration. |
