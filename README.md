# CrowdSec Manager

> ⚠️ **BETA SOFTWARE WARNING** ⚠️
>
> **This software is currently in BETA and should be used with caution.**
>
> - **Always deploy and test on a non-production/test machine first**
> - **Do not use in production environments until thoroughly tested**
> - **Backup your existing configuration before deployment**
> - **Report issues and bugs to help improve the software**
>
> While we strive for stability, beta software may contain bugs, incomplete features, or unexpected behavior. Use at your own risk.

A flexible, multi-proxy web-based management interface for CrowdSec security stack. This project provides a modern, user-friendly web UI built with Go and React for managing your CrowdSec security infrastructure across multiple reverse proxy types.

## Multi-Proxy Support

CrowdSec Manager now supports multiple reverse proxy integrations:

- **Traefik** - Full feature support with whitelist, captcha, log parsing, and bouncer integration
- **Nginx Proxy Manager** - Log parsing and bouncer integration
- **Caddy** - Bouncer integration and health monitoring
- **HAProxy** - SPOA bouncer integration and health monitoring
- **Zoraxy** - Experimental integration with basic health monitoring
- **Standalone** - CrowdSec-only mode without reverse proxy integration

### Backward Compatibility

**Existing Traefik users can upgrade seamlessly** - all current configurations, API endpoints, and environment variables continue to work without any changes required.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8.svg)
![React Version](https://img.shields.io/badge/react-18.3-61DAFB.svg)
![Status](https://img.shields.io/badge/status-beta-orange.svg)

<img width="1200" height="630" alt="Dashboard" src="/images/Dashboard.png"/>
<img width="1200" height="630" alt="Health & Diagnostics" src="/images/Health & Diagnostics.png"/>
<img width="1200" height="630" alt="Whitelist Management" src="/images/Whitelist Management.png"/>
<img width="1200" height="630" alt="IP Management" src="/images/IP Management.png"/>
<img width="1200" height="630" alt="CrowdSec Allowlist Management" src="/images/CrowdSec Allowlist Management.png"/>
<img width="1200" height="630" alt="Scenario Management" src="/images/Scenario Management.png"/>
<img width="1200" height="630" alt="Captcha Setup" src="/images/Captcha Setup.png"/>
<img width="1200" height="630" alt="Decision List Analysis" src="/images/Decision List Analysis.png"/>
<img width="1200" height="630" alt="Alert List Analysis" src="/images/Alert List Analysis.png"/>
<img width="1200" height="630" alt="Logs Viewer" src="/images/Logs Viewer.png"/>
<img width="1200" height="630" alt="Backup Management" src="/images/Backup Management.png"/>
<img width="1200" height="630" alt="System Update" src="/images/System Update.png"/>
<img width="1200" height="630" alt="Cron Job Management" src="/images/Cron Job Management.png"/>
<img width="1200" height="630" alt="Services Management" src="/images/Services Management.png"/>
<img width="1200" height="630" alt="Configuration" src="/images/Configuration.png"/>


## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Docker Compose Setup](#docker-compose-setup)
- [Environment Variables](#environment-variables)
- [Volume Mappings](#volume-mappings)
- [Network Configuration](#network-configuration)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

### Multi-Proxy Architecture

- **Flexible Proxy Support** - Works with Traefik, Nginx Proxy Manager, Caddy, HAProxy, Zoraxy, or standalone
- **Adaptive Interface** - UI automatically adapts to show features available for your selected proxy type
- **Plugin Architecture** - Extensible design allows easy addition of new proxy types
- **Feature Detection** - Automatically detects and enables supported features per proxy type

### Complete Security Management

- **System Health Monitoring** - Real-time container status and diagnostics for all supported proxies
- **IP Management** - Block, unban, and monitor IP addresses across CrowdSec and supported proxies
- **Proxy-Aware Whitelist Management** - Comprehensive IP and CIDR whitelisting with proxy-specific support
- **Decision Management** - View and manage CrowdSec security decisions
- **Bouncer Management** - Monitor CrowdSec bouncers with proxy-specific integration status
- **Modular Architecture** - Run with or without optional components (Pangolin, Gerbil for Traefik)

### Advanced Security Features

- **Custom Scenarios** - Deploy custom CrowdSec detection scenarios
- **Captcha Protection** - Configure Cloudflare Turnstile captcha integration (Traefik)
- **Multi-Proxy Integration** - Seamless CrowdSec integration across different reverse proxy types
- **Console Enrollment** - Easy CrowdSec Console integration

### Monitoring & Logs

- **Real-time Log Streaming** - WebSocket-based live log viewing
- **Multi-Proxy Log Analysis** - Parse and analyze logs from supported proxy types
- **Prometheus Metrics** - View CrowdSec metrics
- **Comprehensive Logging** - View logs from all services with proxy-specific formatting

### Backup & Recovery

- **Automated Backups** - Create full system backups including proxy configurations
- **Scheduled Backups** - Configure cron jobs for automatic backups
- **Easy Restoration** - Restore from any backup with confirmation
- **Retention Management** - Automatic cleanup of old backups

### Stack Updates

- **Version Management** - Update Docker images with custom tags
- **Graceful Updates** - Safe updates with automatic rollback on failure
- **Proxy-Aware Updates** - Update configurations based on selected proxy type

## Prerequisites

Before deploying CrowdSec Manager, ensure you have:

- **Docker** 20.10+ installed and running
- **Docker Compose** 2.0+ installed
- **Network access** to pull Docker images
- **Sufficient disk space** (minimum 2GB recommended)
- **Test environment** for initial deployment (see Beta Warning above)

### System Requirements

- **CPU**: 1 core minimum, 2+ cores recommended
- **RAM**: 512MB minimum, 1GB+ recommended
- **Disk**: 2GB minimum for application and logs
- **Network**: Internet access for Docker image pulls

## Quick Start

### Step 1: Choose Your Deployment Mode

CrowdSec Manager supports two deployment strategies:

1. **Single File Mode** (Recommended) - All services in one docker-compose.yml with profiles
2. **Separate Files Mode** - Core services and proxy services in separate files

### Step 2: Select Your Proxy Type

Choose your reverse proxy integration:

- **Traefik** - Full feature support (whitelist, captcha, logs, bouncer)
- **Nginx Proxy Manager** - Log parsing and bouncer integration
- **Caddy** - Bouncer integration and health monitoring
- **HAProxy** - SPOA bouncer integration
- **Zoraxy** - Experimental support
- **Standalone** - CrowdSec only, no proxy integration

### Step 3: Quick Deployment

#### Single File Mode (Recommended)

```bash
# Clone or download the docker-compose.yml
wget https://raw.githubusercontent.com/hhftechnology/crowdsec_manager/main/docker-compose.yml

# Create required directories
mkdir -p {config,data,logs,backups}
mkdir -p config/{traefik,nginx,caddy,haproxy,zoraxy,crowdsec}
mkdir -p logs/{traefik,nginx,caddy,haproxy,zoraxy}

# Set your proxy type (traefik, nginx, caddy, haproxy, zoraxy, standalone)
export PROXY_TYPE=traefik

# Deploy with your chosen proxy
docker-compose --profile $PROXY_TYPE up -d

# For Traefik with add-ons
docker-compose --profile traefik --profile pangolin --profile gerbil up -d
```

#### Separate Files Mode

```bash
# Deploy core services
docker-compose -f docker-compose.core.yml up -d

# Deploy your chosen proxy
docker-compose -f docker-compose.traefik.yml up -d
# OR
docker-compose -f docker-compose.nginx.yml up -d
# OR
docker-compose -f docker-compose.caddy.yml up -d
```

## Installation

### Step 1: Prepare Your Environment

⚠️ **IMPORTANT**: Deploy to a test machine first before using in production.

1. Set up a test server or VM
2. Install Docker and Docker Compose
3. Ensure you have backups of any existing configurations

### Step 2: Create Required Directories

```bash
# Create base directories
mkdir -p {config,data,logs,backups}

# Create proxy-specific config directories
mkdir -p config/{traefik,nginx,caddy,haproxy,zoraxy,crowdsec}

# Create log directories
mkdir -p logs/{traefik,nginx,caddy,haproxy,zoraxy}

# Set proper permissions
chmod -R 755 {config,data,logs,backups}
```

### Step 3: Configure Environment Variables

Create a `.env` file with your proxy configuration:

```bash
# Multi-Proxy Configuration
PROXY_TYPE=traefik                    # traefik|nginx|caddy|haproxy|zoraxy|standalone
PROXY_ENABLED=true
COMPOSE_MODE=single                   # single|separate

# Proxy-specific container names
TRAEFIK_CONTAINER_NAME=traefik
NPM_CONTAINER_NAME=nginx-proxy-manager
CADDY_CONTAINER_NAME=caddy
HAPROXY_CONTAINER_NAME=haproxy
ZORAXY_CONTAINER_NAME=zoraxy

# Port configurations
MANAGER_PORT=8080
TRAEFIK_HTTP_PORT=80
TRAEFIK_HTTPS_PORT=443
TRAEFIK_DASHBOARD_PORT=8081

# Network configuration
NETWORK_NAME=crowdsec-network

# Optional: Traefik add-ons (only available with Traefik)
PANGOLIN_VERSION=latest
GERBIL_VERSION=latest
```

### Step 4: Deploy Services

#### Single File Deployment (Recommended)

```bash
# Download the main docker-compose.yml
wget https://raw.githubusercontent.com/hhftechnology/crowdsec_manager/main/docker-compose.yml

# Deploy with your chosen proxy profile
docker-compose --profile traefik up -d
# OR
docker-compose --profile nginx up -d
# OR
docker-compose --profile caddy up -d
# OR
docker-compose --profile haproxy up -d
# OR
docker-compose --profile zoraxy up -d
# OR (standalone mode)
docker-compose up -d

# For Traefik with add-ons
docker-compose --profile traefik --profile pangolin --profile gerbil up -d
```

#### Separate Files Deployment

```bash
# Download core and proxy-specific files
wget https://raw.githubusercontent.com/hhftechnology/crowdsec_manager/main/docker-compose.core.yml
wget https://raw.githubusercontent.com/hhftechnology/crowdsec_manager/main/docker-compose.traefik.yml

# Deploy core services first
docker-compose -f docker-compose.core.yml up -d

# Deploy your chosen proxy
docker-compose -f docker-compose.traefik.yml up -d
```

### Step 5: Verify Installation

1. Check all containers are running:

   ```bash
   docker-compose ps
   ```

2. Check container health:

   ```bash
   curl http://localhost:8080/api/health/stack
   ```

3. Access the web interface:
   - Open your browser to `http://your-server-ip:8080`
   - The interface will automatically adapt to your selected proxy type

### Step 6: Initial Configuration

1. **Proxy Detection**: The system automatically detects your proxy type and available features
2. **Feature Availability**: The UI shows only features supported by your selected proxy
3. **Migration**: Existing Traefik users will see their configurations automatically migrated

## Migration from Previous Versions

**Existing Traefik users**: Your installation will automatically upgrade with zero configuration changes required. See [MIGRATION.md](MIGRATION.md) for detailed migration information.

**New installations**: Follow the Quick Start guide above to deploy with your preferred proxy type.

## Configuration

### Environment Variables

The following environment variables can be configured in your `.env` file or `docker-compose.yml`:

#### Multi-Proxy Configuration

| Variable                | Default     | Description                                                    |
| ----------------------- | ----------- | -------------------------------------------------------------- |
| `PROXY_TYPE`            | `traefik`   | Proxy type: `traefik`, `nginx`, `caddy`, `haproxy`, `zoraxy`, `standalone` |
| `PROXY_ENABLED`         | `true`      | Enable proxy integration (`true`/`false`)                     |
| `PROXY_CONTAINER_NAME`  | (varies)    | Container name for the selected proxy                         |
| `COMPOSE_MODE`          | `single`    | Deployment mode: `single` (profiles) or `separate` (files)    |

#### Proxy-Specific Container Names

| Variable                  | Default                 | Description                        |
| ------------------------- | ----------------------- | ---------------------------------- |
| `TRAEFIK_CONTAINER_NAME`  | `traefik`               | Traefik container name             |
| `NPM_CONTAINER_NAME`      | `nginx-proxy-manager`   | Nginx Proxy Manager container name |
| `CADDY_CONTAINER_NAME`    | `caddy`                 | Caddy container name               |
| `HAPROXY_CONTAINER_NAME`  | `haproxy`               | HAProxy container name             |
| `ZORAXY_CONTAINER_NAME`   | `zoraxy`                | Zoraxy container name              |

#### Server Configuration

| Variable      | Default                          | Description                                               |
| ------------- | -------------------------------- | --------------------------------------------------------- |
| `PORT`        | `8080`                           | Port on which the API server listens (exposed internally) |
| `ENVIRONMENT` | `production`                     | Environment mode (`development` or `production`)          |
| `LOG_LEVEL`   | `info`                           | Logging level: `debug`, `info`, `warn`, `error`           |
| `LOG_FILE`    | `/app/logs/crowdsec-manager.log` | Path to log file inside container                         |

#### Docker Configuration

| Variable       | Default                       | Description                                 |
| -------------- | ----------------------------- | ------------------------------------------- |
| `DOCKER_HOST`  | `unix:///var/run/docker.sock` | Docker daemon socket path                   |
| `COMPOSE_FILE` | `/app/docker-compose.yml`     | Path to docker-compose.yml inside container |
| `CONFIG_DIR`   | `/app/config`                 | Configuration directory path                |

#### Database Configuration

| Variable        | Default                 | Description               |
| --------------- | ----------------------- | ------------------------- |
| `DATABASE_PATH` | `/app/data/settings.db` | SQLite database file path |

#### Legacy Traefik Configuration (Backward Compatibility)

| Variable                 | Default                           | Description                             |
| ------------------------ | --------------------------------- | --------------------------------------- |
| `TRAEFIK_DYNAMIC_CONFIG` | `/etc/traefik/dynamic_config.yml` | Traefik dynamic configuration file path |
| `TRAEFIK_STATIC_CONFIG`  | `/etc/traefik/traefik_config.yml` | Traefik static configuration file path  |
| `TRAEFIK_ACCESS_LOG`     | `/var/log/traefik/access.log`     | Traefik access log file path            |
| `TRAEFIK_ERROR_LOG`      | `/var/log/traefik/traefik.log`    | Traefik error log file path             |

#### CrowdSec Configuration

| Variable               | Default                     | Description                                     |
| ---------------------- | --------------------------- | ----------------------------------------------- |
| `CROWDSEC_ACQUIS_FILE` | `/etc/crowdsec/acquis.yaml` | CrowdSec acquisition file path                  |
| `INCLUDE_CROWDSEC`     | `true`                      | Include CrowdSec in operations (`true`/`false`) |

#### Traefik Add-ons (Only available when PROXY_TYPE=traefik)

| Variable           | Default | Description                                |
| ------------------ | ------- | ------------------------------------------ |
| `INCLUDE_PANGOLIN` | `false` | Include Pangolin service (`true`/`false`) |
| `INCLUDE_GERBIL`   | `false` | Include Gerbil service (`true`/`false`)   |

#### Backup Configuration

| Variable         | Default        | Description                                          |
| ---------------- | -------------- | ---------------------------------------------------- |
| `BACKUP_DIR`     | `/app/backups` | Directory for storing backups                        |
| `RETENTION_DAYS` | `60`           | Number of days to retain backups before auto-cleanup |

#### Port Configuration

| Variable                  | Default | Description                    |
| ------------------------- | ------- | ------------------------------ |
| `MANAGER_PORT`            | `8080`  | CrowdSec Manager web interface |
| `TRAEFIK_HTTP_PORT`       | `80`    | Traefik HTTP port              |
| `TRAEFIK_HTTPS_PORT`      | `443`   | Traefik HTTPS port             |
| `TRAEFIK_DASHBOARD_PORT`  | `8081`  | Traefik dashboard port         |
| `NPM_HTTP_PORT`           | `80`    | NPM HTTP port                  |
| `NPM_HTTPS_PORT`          | `443`   | NPM HTTPS port                 |
| `NPM_ADMIN_PORT`          | `81`    | NPM admin interface port       |
| `CADDY_HTTP_PORT`         | `80`    | Caddy HTTP port                |
| `CADDY_HTTPS_PORT`        | `443`   | Caddy HTTPS port               |
| `CADDY_ADMIN_PORT`        | `2019`  | Caddy admin API port           |

### Volume Mappings
For a detailed explanation of volume mappings, directory structure, and permissions, please refer to [VOLUMES_AND_PATHS.md](VOLUMES_AND_PATHS.md).

### Network Configuration

The application uses an external Docker network named `pangolin`. This network should connect all related services (CrowdSec, Traefik, Pangolin, Gerbil, etc.).

#### Creating the Network

If the network doesn't exist, create it:

```bash
docker network create pangolin
```

#### Verifying Network

Check that the network exists and the container is connected:

```bash
# List networks
docker network ls | grep pangolin

# Inspect network
docker network inspect pangolin

# Check container network
docker inspect crowdsec-manager | grep -A 10 Networks
```

#### Port Exposure

The container exposes port `8080` internally. To access the web interface:

1. **Direct Access** (if port is published):

   ```yaml
   ports:
     - "8080:8080"
   ```

2. **Via Tailscale/WireGuard** (recommended)


## Usage

### Accessing the Web Interface

Once the containers are running, access the web interface:

- **Direct Access**: `http://your-server-ip:8080`
- **Via Reverse Proxy**: Configure your proxy to route to the CrowdSec Manager service

### Initial Setup

1. **Health Check**: Verify all services are running

   ```bash
   curl http://localhost:8080/api/health/stack
   ```

2. **Proxy Detection**: The system automatically detects your proxy type and available features

3. **View Dashboard**: Open the web interface in your browser - the UI will adapt to your proxy type

4. **Configure Services**: Use the adaptive UI to:
   - Check system health (all proxy types)
   - Configure proxy-specific features
   - Set up backups
   - Monitor logs

### Proxy-Specific Features

#### Traefik (Full Feature Support)
- Whitelist management via dynamic configuration
- Captcha protection with Cloudflare Turnstile
- Advanced log parsing and analysis
- Bouncer integration monitoring
- Optional Pangolin/Gerbil add-ons

#### Nginx Proxy Manager
- Log parsing from NPM log files
- cs-nginx-bouncer integration monitoring
- Health status checking

#### Caddy
- caddy-crowdsec-bouncer module integration
- Basic health monitoring
- Configuration validation

#### HAProxy
- SPOA bouncer integration monitoring
- Socket connectivity checking
- Health status monitoring

#### Zoraxy (Experimental)
- Basic health monitoring
- Experimental bouncer integration

#### Standalone Mode
- CrowdSec-only features
- No proxy integration
- Core security management

### Common Operations

#### Whitelist Current IP (Proxy-Aware)

```bash
# Generic API (works with all proxy types)
curl -X POST http://localhost:8080/api/whitelist/current \
  -H "Content-Type: application/json" \
  -d '{"add_to_crowdsec": true, "add_to_proxy": true}'

# Legacy API (backward compatible)
curl -X POST http://localhost:8080/api/whitelist/current \
  -H "Content-Type: application/json" \
  -d '{"add_to_crowdsec": true, "add_to_traefik": true}'
```

#### Check Proxy Information

```bash
# Get current proxy type and features
curl http://localhost:8080/api/proxy/current

# Get available proxy types
curl http://localhost:8080/api/proxy/types

# Get supported features for current proxy
curl http://localhost:8080/api/proxy/features
```

#### Check IP Security Status

```bash
curl http://localhost:8080/api/ip/security/1.2.3.4
```

#### Create Backup

```bash
curl -X POST http://localhost:8080/api/backup/create \
  -H "Content-Type: application/json" \
  -d '{"dry_run": false}'
```

#### View System Health

```bash
curl http://localhost:8080/api/health/complete
```

### Adaptive Web Interface Features

The web interface automatically adapts based on your proxy type:

- **Dashboard**: Overview of system status with proxy-specific information
- **IP Management**: Block/unban IPs, check security status
- **Proxy-Aware Whitelist Management**: Shows available whitelist options for your proxy type
- **Adaptive Log Viewer**: Displays logs with proxy-specific parsing when supported
- **Feature-Based Navigation**: Menu items show/hide based on proxy capabilities
- **Proxy Health Monitoring**: Displays proxy-specific health information
- **Backups**: Create, restore, and manage backups including proxy configurations
- **Updates**: Update Docker images and services with proxy awareness
- **Configuration**: Manage CrowdSec and proxy-specific settings

## API Documentation

### Multi-Proxy Management

- `GET /api/proxy/types` - Get available proxy types
- `GET /api/proxy/current` - Get current proxy information and features
- `POST /api/proxy/configure` - Configure proxy settings
- `GET /api/proxy/features` - Get supported features for current proxy

### Health & Diagnostics

- `GET /api/health/stack` - Check all container statuses (proxy-aware)
- `GET /api/health/complete` - Complete system diagnostics including proxy health
- `GET /api/health/proxy` - Proxy-specific health information

### IP Management

- `GET /api/ip/public` - Get current public IP
- `GET /api/ip/blocked/:ip` - Check if IP is blocked
- `GET /api/ip/security/:ip` - Comprehensive IP security check
- `POST /api/ip/unban` - Unban an IP address

### Proxy-Aware Whitelist Management

- `GET /api/whitelist/view` - View all whitelisted IPs (proxy-aware)
- `POST /api/whitelist/current` - Whitelist current public IP (supports both legacy and new fields)
- `POST /api/whitelist/manual` - Whitelist specific IP (proxy-aware)
- `POST /api/whitelist/cidr` - Whitelist CIDR range (proxy-aware)
- `POST /api/whitelist/crowdsec` - Add to CrowdSec whitelist
- `POST /api/whitelist/traefik` - Add to Traefik whitelist (legacy, maintained for compatibility)
- `POST /api/whitelist/proxy` - Add to current proxy whitelist (generic)
- `POST /api/whitelist/comprehensive` - Setup full whitelist (proxy-aware)

### Backup Management

- `GET /api/backup/list` - List all backups
- `POST /api/backup/create` - Create new backup (includes proxy configurations)
- `POST /api/backup/restore` - Restore from backup (proxy-aware)
- `DELETE /api/backup/:id` - Delete backup
- `POST /api/backup/cleanup` - Remove old backups
- `GET /api/backup/latest` - Get latest backup

### Multi-Proxy Logs & Monitoring

- `GET /api/logs/crowdsec` - Get CrowdSec logs
- `GET /api/logs/proxy` - Get current proxy logs (generic endpoint)
- `GET /api/logs/traefik` - Get Traefik logs (legacy, maintained for compatibility)
- `GET /api/logs/nginx` - Get Nginx Proxy Manager logs
- `GET /api/logs/caddy` - Get Caddy logs
- `GET /api/logs/haproxy` - Get HAProxy logs
- `GET /api/logs/zoraxy` - Get Zoraxy logs
- `GET /api/logs/proxy/advanced` - Advanced proxy log analysis (when supported)
- `GET /api/logs/:service` - Get service logs
- `GET /api/logs/stream/:service` - Stream logs (WebSocket)

### Bouncer Management

- `GET /api/bouncer/status` - Get bouncer status for current proxy type
- `GET /api/bouncer/traefik` - Get Traefik bouncer status (legacy)
- `GET /api/bouncer/nginx` - Get Nginx bouncer status
- `GET /api/bouncer/caddy` - Get Caddy bouncer status
- `GET /api/bouncer/haproxy` - Get HAProxy bouncer status

### Captcha Management (Traefik Only)

- `GET /api/captcha/status` - Get captcha configuration status
- `POST /api/captcha/setup` - Configure captcha protection
- `DELETE /api/captcha/disable` - Disable captcha protection

### Backward Compatibility

All legacy API endpoints continue to work unchanged. New generic endpoints provide the same functionality with proxy-agnostic field names while maintaining backward compatibility by supporting both old and new field formats.

**Example**: The whitelist endpoint accepts both `add_to_traefik` (legacy) and `add_to_proxy` (new) fields, with responses including both formats.

For detailed API schemas and examples, see [REVERSE_PROXIES.md](REVERSE_PROXIES.md).

## Development

### Building from Source

**Backend:**

```bash
go build -o crowdsec-manager ./cmd/server
```

**Frontend:**

```bash
cd web
npm install
npm run build
```

**Docker Image:**

```bash
docker build -t crowdsec-manager:latest .
```

### Running Tests

**Backend:**

```bash
go test -v ./...
```

**Frontend:**

```bash
cd web
npm run lint
npm test
```

### Development Mode

Use `docker-compose.dev.yml` for development with hot reload:

```bash
docker-compose -f docker-compose.dev.yml up
```

## Troubleshooting

### Container Won't Start

**Check logs:**

```bash
docker logs crowdsec-manager
```

**Verify Docker socket:**

```bash
ls -la /var/run/docker.sock
```

**Check permissions:**

```bash
# Ensure Docker socket is accessible
sudo chmod 666 /var/run/docker.sock
# Or add user to docker group
sudo usermod -aG docker $USER
```

### Network Issues

**Verify network exists:**

```bash
docker network ls | grep pangolin
```

**Create network if missing:**

```bash
docker network create pangolin
```

**Check container network:**

```bash
docker inspect crowdsec-manager | grep -A 10 Networks
```

### Volume Mount Issues

**Check directory permissions:**

```bash
# Ensure directories exist
sudo mkdir -p /root/config
sudo mkdir -p /root/config/traefik/logs

# Check permissions
ls -la /root/config
ls -la ./backups
ls -la ./data
```

**Fix permissions if needed:**

```bash
sudo chown -R $USER:$USER ./backups ./data
sudo chmod -R 755 ./backups ./data
```

### Port Already in Use

If port 8080 is already in use:

1. **Change the port** in docker-compose.yml:

   ```yaml
   ports:
     - "8090:8080"
   ```

2. **Or find and stop the conflicting service:**
   ```bash
   sudo lsof -i :8080
   sudo kill <PID>
   ```

### Database Issues

**Check database file:**

```bash
ls -la ./data/settings.db
```

**Reset database (⚠️ data loss):**

```bash
rm ./data/settings.db
docker-compose restart crowdsec-manager
```

### Backup Failures

**Check backup directory:**

```bash
ls -la ./backups
```

**Verify permissions:**

```bash
chmod 755 ./backups
```

**Check disk space:**

```bash
df -h
```

### Log Access Issues

**Verify Traefik log paths:**

```bash
ls -la /root/config/traefik/logs/
```

**Check log file permissions:**

```bash
sudo chmod 644 /root/config/traefik/logs/*.log
```

### Container Health Check Fails

**Manual health check:**

```bash
curl http://localhost:8080/health
```

**Check container status:**

```bash
docker ps -a | grep crowdsec-manager
```

**Restart container:**

```bash
docker-compose restart crowdsec-manager
```

## Testing Recommendations

Before deploying to production:

1. **Test on a dedicated test server**

   - Use a VM or separate server
   - Don't use your production infrastructure

2. **Test all features**

   - IP management
   - Whitelist operations
   - Backup creation and restoration
   - Log viewing
   - Service updates

3. **Monitor resource usage**

   - CPU and memory consumption
   - Disk space for backups
   - Network traffic

4. **Test failure scenarios**

   - Container restarts
   - Network disconnections
   - Disk space exhaustion
   - Permission issues

5. **Verify backups**

   - Create backups
   - Test restoration
   - Verify data integrity

6. **Check integration**
   - CrowdSec integration
   - Traefik integration
   - Log aggregation
   - Service discovery

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Documentation

### Complete Documentation Suite

- **[MIGRATION.md](MIGRATION.md)** - Migration guide for existing Traefik users
- **[REVERSE_PROXIES.md](REVERSE_PROXIES.md)** - Detailed proxy-specific integration guides
- **[DEPLOYMENT.md](DEPLOYMENT.md)** - Docker Compose deployment strategies
- **[VOLUMES_AND_PATHS.md](VOLUMES_AND_PATHS.md)** - Volume mappings and directory structure
- **[USAGE.md](USAGE.md)** - Detailed usage instructions and examples
- **[docs/architecture.md](docs/architecture.md)** - Backend and frontend architecture, package structure, and how to extend
- **[docs/api-migration.md](docs/api-migration.md)** - Deprecated API endpoints, replacements, and sunset timeline

### Quick Reference

- **Multi-Proxy Support**: Choose from Traefik, Nginx Proxy Manager, Caddy, HAProxy, Zoraxy, or Standalone
- **Backward Compatibility**: Existing Traefik installations work without changes
- **Adaptive UI**: Interface automatically adapts to your proxy type's capabilities
- **Feature Detection**: System shows only features supported by your selected proxy

## Support

- **Issues**: [GitHub Issues](https://github.com/hhftechnology/crowdsec_manager/issues)
- **Discussions**: [GitHub Discussions](https://github.com/hhftechnology/crowdsec_manager/discussions)
- **Documentation**: See the complete documentation suite above
- **Migration Help**: Check [MIGRATION.md](MIGRATION.md) for upgrade guidance

## Acknowledgments

- Original bash script by hhf-technology
- CrowdSec for the security engine
- Multiple reverse proxy communities (Traefik, Nginx, Caddy, HAProxy, Zoraxy)
- Shadcn/ui for UI components
- The open-source community for continuous feedback and contributions

---

**⚠️ Remember: This is BETA software. Always test on a non-production environment first!**

**Built with ❤️ for the CrowdSec community**

## What's New in Multi-Proxy Version

- ✅ **Six Proxy Types Supported**: Traefik, Nginx Proxy Manager, Caddy, HAProxy, Zoraxy, Standalone
- ✅ **100% Backward Compatibility**: Existing Traefik installations work unchanged
- ✅ **Adaptive User Interface**: UI automatically shows features available for your proxy type
- ✅ **Plugin Architecture**: Extensible design for adding new proxy types
- ✅ **Comprehensive Documentation**: Complete guides for all proxy types and migration scenarios
- ✅ **Docker Compose Profiles**: Flexible deployment with single-file or separate-file strategies
- ✅ **Feature Detection**: Automatic detection of proxy capabilities and graceful degradation
- ✅ **Enhanced Health Monitoring**: Proxy-specific health checks and diagnostics
