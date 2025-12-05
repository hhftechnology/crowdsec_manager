<div align="center">
    <h1 align="center"><a href="https://github.com/hhftechnology/crowdsec_manager">CrowdSec Manager</a></h1>
</div>


<div align="center">
    
[![Docker](https://img.shields.io/docker/pulls/hhftechnology/crowdsec-manager?style=flat-square)](https://hub.docker.com/r/hhftechnology/crowdsec-manager)
![Stars](https://img.shields.io/github/stars/hhftechnology/crowdsec_manager?style=flat-square)
[![Discord](https://img.shields.io/discord/994247717368909884?logo=discord&style=flat-square)](https://discord.gg/HDCt9MjyMJ)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8.svg)
![React Version](https://img.shields.io/badge/react-18.3-61DAFB.svg)
![Status](https://img.shields.io/badge/status-beta-orange.svg)

**A web-based management interface for CrowdSec security stack with Pangolin integration. This project provides a modern, user-friendly web UI built with Go and React for managing your CrowdSec security infrastructure.**

</div>


> ⚠️ **BETA SOFTWARE WARNING** ⚠️
>
> **This software is currently in BETA and should be used with caution.**
>
> - **Always deploy and test on a non-production/test machine first**
> - **Do not use in production environments until thoroughly tested**
> - **Backup your existing configuration before deployment**
> - **Report issues and bugs to help improve the software**
>
> While we strive for stability, beta software may contain bugs, incomplete features, or unexpected behavior. Use at your own risk..




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

### Complete Security Management

- **System Health Monitoring** - Real-time container status and diagnostics
- **IP Management** - Block, unban, and monitor IP addresses
- **Whitelist Management** - Comprehensive IP and CIDR whitelisting for CrowdSec and Traefik
- **Decision Management** - View and manage CrowdSec security decisions
- **Bouncer Management** - Monitor CrowdSec bouncers and their status
- **Modular Architecture** - Run with or without optional components (Pangolin, Gerbil)

### Advanced Security Features

- **Custom Scenarios** - Deploy custom CrowdSec detection scenarios
- **Captcha Protection** - Configure Cloudflare Turnstile captcha integration
- **Traefik Integration** - Seamless CrowdSec-Traefik middleware configuration
- **Console Enrollment** - Easy CrowdSec Console integration

### Monitoring & Logs

- **Real-time Log Streaming** - WebSocket-based live log viewing
- **Advanced Log Analysis** - Analyze Traefik logs with statistics
- **Prometheus Metrics** - View CrowdSec metrics
- **Multi-service Logs** - View logs from all services (CrowdSec, Traefik, Pangolin, Gerbil)

### Backup & Recovery

- **Automated Backups** - Create full system backups
- **Scheduled Backups** - Configure cron jobs for automatic backups
- **Easy Restoration** - Restore from any backup with confirmation
- **Retention Management** - Automatic cleanup of old backups

### Stack Updates

- **Version Management** - Update Docker images with custom tags
- **Graceful Updates** - Safe updates with automatic rollback on failure
- **Flexible Configuration** - Update with or without CrowdSec

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

## Installation

### Step 1: Prepare Your Test Environment

⚠️ **IMPORTANT**: Deploy to a test machine first before using in production.

1. Set up a test server or VM
2. Install Docker and Docker Compose
3. Ensure you have backups of any existing configurations

### Step 2: Create Required Directories

```bash
# Create configuration directory
sudo mkdir -p /root/config
sudo mkdir -p /root/config/traefik/logs

# Create backup directory (in your project directory)
mkdir -p ./backups

# Create data directory (in your project directory)
mkdir -p ./data
```

### Step 3: Prepare Docker Compose File

Create or update your `docker-compose.yml` file with the following configuration:

```yaml

services:
  crowdsec-manager:
    image: hhftechnology/crowdsec-manager:latest
    container_name: crowdsec-manager
    restart: unless-stopped
    expose:
      - "8080"
    environment:
      - PORT=8080
      - ENVIRONMENT=production
      - DOCKER_HOST=unix:///var/run/docker.sock
      - COMPOSE_FILE=/app/docker-compose.yml
      - PANGOLIN_DIR=/app
      - CONFIG_DIR=/app/config
      - DATABASE_PATH=/app/data/settings.db
      - TRAEFIK_DYNAMIC_CONFIG=/dynamic_config.yml
      - TRAEFIK_STATIC_CONFIG=/etc/traefik/traefik_config.yml
      - TRAEFIK_ACCESS_LOG=/var/log/traefik/access.log
      - TRAEFIK_ERROR_LOG=/var/log/traefik/traefik.log
      - CROWDSEC_ACQUIS_FILE=/etc/crowdsec/acquis.yaml
      - BACKUP_DIR=/app/backups
      - RETENTION_DAYS=60
      - INCLUDE_CROWDSEC=false
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /root/config:/app/config
      - /root/docker-compose.yml:/app/docker-compose.yml
      - ./backups:/app/backups
      - /root/config/traefik/logs:/app/logs
      - ./data:/app/data
      - /root/config/traefik/logs:/var/log/traefik
    networks:
      - pangolin

networks:
  pangolin:
    external: true
```

### Step 4: Ensure External Network Exists

The compose file requires an external network named `pangolin`. Create it if it doesn't exist:

```bash
docker network create pangolin
```

Or if you're using an existing network, ensure it's properly configured.

### Step 5: Deploy the Container

```bash
# Pull the latest image
docker pull hhftechnology/crowdsec-manager:latest

# Start the container
docker-compose up -d

# Check container status
docker ps | grep crowdsec-manager

# View logs
docker logs -f crowdsec-manager
```

### Step 6: Verify Installation

1. Check container health:

   ```bash
   curl http://localhost:8080/health
   ```

2. Access the web interface:
   - Open your browser to `http://your-server-ip:8080`
   - Or configure Traefik routing (see Network Configuration section)

## Configuration

### Environment Variables

The following environment variables can be configured in your `docker-compose.yml`:

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
| `PANGOLIN_DIR` | `/app`                        | Base directory for Pangolin operations      |
| `CONFIG_DIR`   | `/app/config`                 | Configuration directory path                |

#### Database Configuration

| Variable        | Default                 | Description               |
| --------------- | ----------------------- | ------------------------- |
| `DATABASE_PATH` | `/app/data/settings.db` | SQLite database file path |

#### Traefik Configuration Paths

| Variable                 | Default                           | Description                             |
| ------------------------ | --------------------------------- | --------------------------------------- |
| `TRAEFIK_DYNAMIC_CONFIG` | `/dynamic_config.yml`             | Traefik dynamic configuration file path |
| `TRAEFIK_STATIC_CONFIG`  | `/etc/traefik/traefik_config.yml` | Traefik static configuration file path  |
| `TRAEFIK_ACCESS_LOG`     | `/var/log/traefik/access.log`     | Traefik access log file path            |
| `TRAEFIK_ERROR_LOG`      | `/var/log/traefik/traefik.log`    | Traefik error log file path             |

#### CrowdSec Configuration

| Variable               | Default                     | Description                                     |
| ---------------------- | --------------------------- | ----------------------------------------------- |
| `CROWDSEC_ACQUIS_FILE` | `/etc/crowdsec/acquis.yaml` | CrowdSec acquisition file path                  |
| `INCLUDE_CROWDSEC`     | `false`                     | Include CrowdSec in operations (`true`/`false`) |
| `INCLUDE_PANGOLIN`     | `true`                      | Include Pangolin service (`true`/`false`)       |
| `INCLUDE_GERBIL`       | `true`                      | Include Gerbil service (`true`/`false`)         |

#### Backup Configuration

| Variable         | Default        | Description                                          |
| ---------------- | -------------- | ---------------------------------------------------- |
| `BACKUP_DIR`     | `/app/backups` | Directory for storing backups                        |
| `RETENTION_DAYS` | `60`           | Number of days to retain backups before auto-cleanup |

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

Once the container is running, access the web interface:

- **Via Tailscale/WireGuard**: `http://your-tailscale-ip:8080` ( port has to be published)

### Initial Setup

1. **Health Check**: Verify the service is running

   ```bash
   curl http://localhost:8080/api/health/stack
   ```

2. **View Dashboard**: Open the web interface in your browser

3. **Configure Services**: Use the UI to:
   - Check system health
   - Configure whitelists
   - Set up backups
   - Monitor logs

### Common Operations

#### Whitelist Current IP

```bash
curl -X POST http://localhost:8080/api/whitelist/current \
  -H "Content-Type: application/json" \
  -d '{"add_to_crowdsec": true, "add_to_traefik": true}'
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

### Web Interface Features

- **Dashboard**: Overview of system status
- **IP Management**: Block/unban IPs, check security status
- **Whitelist Management**: Manage IP and CIDR whitelists
- **Logs**: View and stream logs from all services
- **Backups**: Create, restore, and manage backups
- **Updates**: Update Docker images and services
- **Configuration**: Manage CrowdSec and Traefik settings

## API Documentation

### Health & Diagnostics

- `GET /api/health/stack` - Check all container statuses
- `GET /api/health/complete` - Complete system diagnostics

### IP Management

- `GET /api/ip/public` - Get current public IP
- `GET /api/ip/blocked/:ip` - Check if IP is blocked
- `GET /api/ip/security/:ip` - Comprehensive IP security check
- `POST /api/ip/unban` - Unban an IP address

### Whitelist Management

- `GET /api/whitelist/view` - View all whitelisted IPs
- `POST /api/whitelist/current` - Whitelist current public IP
- `POST /api/whitelist/manual` - Whitelist specific IP
- `POST /api/whitelist/cidr` - Whitelist CIDR range
- `POST /api/whitelist/crowdsec` - Add to CrowdSec whitelist
- `POST /api/whitelist/traefik` - Add to Traefik whitelist
- `POST /api/whitelist/comprehensive` - Setup full whitelist

### Backup Management

- `GET /api/backup/list` - List all backups
- `POST /api/backup/create` - Create new backup
- `POST /api/backup/restore` - Restore from backup
- `DELETE /api/backup/:id` - Delete backup
- `POST /api/backup/cleanup` - Remove old backups
- `GET /api/backup/latest` - Get latest backup

### Logs & Monitoring

- `GET /api/logs/crowdsec` - Get CrowdSec logs
- `GET /api/logs/traefik` - Get Traefik logs
- `GET /api/logs/traefik/advanced` - Advanced log analysis
- `GET /api/logs/:service` - Get service logs
- `GET /api/logs/stream/:service` - Stream logs (WebSocket)

For complete API documentation, see the [API Documentation](#api-documentation) section in the original README.

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

## Support

- **Issues**: [GitHub Issues](https://github.com/hhftechnology/crowdsec_manager/issues)
- **Discussions**: [GitHub Discussions](https://github.com/hhftechnology/crowdsec_manager/discussions)

## Acknowledgments

- Original bash script by hhf-technology
- CrowdSec for the security engine
- Traefik for reverse proxy
- Shadcn/ui for UI components

---

**⚠️ Remember: This is BETA software. Always test on a non-production environment first!**

**Built with ❤️ for the CrowdSec community**
