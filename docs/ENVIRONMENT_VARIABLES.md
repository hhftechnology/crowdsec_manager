# Environment Variables

The CrowdSec Manager application is configured using the following environment variables. These can be set in your shell or in a `.env` file.

## Server Configuration

| Variable | Description | Default Value | Required |
|----------|-------------|---------------|----------|
| `PORT` | The port the server listens on. | `8080` | No |
| `ENVIRONMENT` | The application environment (`development` or `production`). | `development` | No |
| `LOG_LEVEL` | Logging level (`debug`, `info`, `warn`, `error`). | `info` | No |
| `LOG_FILE` | Path to the log file. | `./logs/crowdsec-manager.log` | No |
| `SHUTDOWN_TIMEOUT` | Graceful shutdown timeout in seconds. | `30` | No |
| `READ_TIMEOUT` | HTTP read timeout in seconds. | `15` | No |
| `WRITE_TIMEOUT` | HTTP write timeout in seconds. | `15` | No |

## Docker & Paths

| Variable | Description | Default Value | Required |
|----------|-------------|---------------|----------|
| `DOCKER_HOST` | Docker socket path or TCP URL (e.g., `unix:///var/run/docker.sock`). | `""` (local socket) | No |
| `COMPOSE_FILE` | Path to the `docker-compose.yml` file. | `./docker-compose.yml` | No |
| `PANGOLIN_DIR` | Directory containing Pangolin configuration. | `.` | No |
| `CONFIG_DIR` | Directory for application configuration files. | `./config` | No |
| `DATABASE_PATH` | Path to the SQLite settings database. | `./data/settings.db` | No |
| `BACKUP_DIR` | Directory where backups are stored. | `./backups` | No |
| `RETENTION_DAYS` | Number of days to keep backups. | `60` | No |

## Service Integration

| Variable | Description | Default Value | Required |
|----------|-------------|---------------|----------|
| `INCLUDE_CROWDSEC` | Whether to manage CrowdSec. | `true` | No |
| `INCLUDE_PANGOLIN` | Whether to manage Pangolin. | `true` | No |
| `INCLUDE_GERBIL` | Whether to manage Gerbil. | `true` | No |

## Container Names

| Variable | Description | Default Value | Required |
|----------|-------------|---------------|----------|
| `CROWDSEC_CONTAINER_NAME` | Name of the CrowdSec container. | `crowdsec` | No |
| `PANGOLIN_CONTAINER_NAME` | Name of the Pangolin container. | `pangolin` | No |
| `GERBIL_CONTAINER_NAME` | Name of the Gerbil container. | `gerbil` | No |
| `TRAEFIK_CONTAINER_NAME` | Name of the Traefik container. | `traefik` | No |

## CrowdSec LAPI

| Variable | Description | Default Value | Required |
|----------|-------------|---------------|----------|
| `CROWDSEC_LAPI_URL` | URL of the CrowdSec Local API. | `http://crowdsec:8080` | No |
| `CROWDSEC_LAPI_KEY` | API Key for the CrowdSec Local API. | `""` | Yes (if using LAPI features) |

## File Paths (Internal)

| Variable | Description | Default Value | Required |
|----------|-------------|---------------|----------|
| `TRAEFIK_DYNAMIC_CONFIG` | Path to Traefik dynamic config file. | `/etc/traefik/dynamic_config.yml` | No |
| `TRAEFIK_STATIC_CONFIG` | Path to Traefik static config file. | `/etc/traefik/traefik_config.yml` | No |
| `TRAEFIK_ACCESS_LOG` | Path to Traefik access log. | `/var/log/traefik/access.log` | No |
| `TRAEFIK_ERROR_LOG` | Path to Traefik error log. | `/var/log/traefik/traefik.log` | No |
| `CROWDSEC_ACQUIS_FILE` | Path to CrowdSec acquisition file. | `/etc/crowdsec/acquis.yaml` | No |
