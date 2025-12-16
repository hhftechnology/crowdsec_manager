# CrowdSec Manager - Deployment Templates

This directory contains production-ready deployment templates for CrowdSec Manager with different reverse proxy configurations.

## Available Templates

### Single Proxy Deployments

| Template | Description | Features | Use Case |
|----------|-------------|----------|----------|
| **[docker-compose.traefik.yml](docker-compose.traefik.yml)** | Traefik with full features | Whitelist, Captcha, Logs, Bouncer | Full-featured reverse proxy |
| **[docker-compose.nginx.yml](docker-compose.nginx.yml)** | Nginx Proxy Manager | Logs, Bouncer | User-friendly web UI proxy |
| **[docker-compose.caddy.yml](docker-compose.caddy.yml)** | Caddy reverse proxy | Bouncer, Health | Simple, automatic HTTPS |
| **[docker-compose.haproxy.yml](docker-compose.haproxy.yml)** | HAProxy load balancer | Bouncer, Health | High-performance load balancing |
| **[docker-compose.standalone.yml](docker-compose.standalone.yml)** | CrowdSec only | Health monitoring | API-only, no proxy needed |

### Multi-Service Deployments

| Template | Description | Components | Use Case |
|----------|-------------|------------|----------|
| **[docker-compose.traefik-full.yml](docker-compose.traefik-full.yml)** | Traefik with add-ons | Traefik + Pangolin + Gerbil | Complete security stack |
| **[docker-compose.separate.yml](docker-compose.separate.yml)** | Separate file deployment | Core + Proxy files | Microservices architecture |

## Quick Start

### 1. Choose Your Template

Select the template that matches your reverse proxy:

```bash
# For Traefik users
cp deployment-templates/docker-compose.traefik.yml docker-compose.yml

# For Nginx Proxy Manager users  
cp deployment-templates/docker-compose.nginx.yml docker-compose.yml

# For standalone deployment
cp deployment-templates/docker-compose.standalone.yml docker-compose.yml
```

### 2. Configure Environment

Copy and customize the environment file:

```bash
# Copy example configuration
cp examples/traefik/.env .env  # or nginx/.env, standalone/.env

# Edit configuration
nano .env
```

### 3. Deploy Services

```bash
# Start all services
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f crowdsec-manager
```

## Configuration Guide

### Core Settings

All templates support these core environment variables:

```bash
# Deployment Configuration
COMPOSE_MODE=single              # single|separate
ENVIRONMENT=production           # production|development
LOG_LEVEL=info                  # debug|info|warn|error

# Network Configuration
NETWORK_NAME=crowdsec-network   # Docker network name
MANAGER_PORT=8080               # CrowdSec Manager port

# Backup Configuration
RETENTION_DAYS=60               # Backup retention period
INCLUDE_CROWDSEC=true          # Include CrowdSec in backups
```

### Proxy-Specific Settings

#### Traefik Configuration
```bash
PROXY_TYPE=traefik
TRAEFIK_VERSION=latest
TRAEFIK_CONTAINER_NAME=traefik
TRAEFIK_HTTP_PORT=80
TRAEFIK_HTTPS_PORT=443
TRAEFIK_DASHBOARD_PORT=8081
TRAEFIK_API_INSECURE=true
TRAEFIK_LOG_LEVEL=INFO
```

#### Nginx Proxy Manager Configuration
```bash
PROXY_TYPE=nginx
NPM_VERSION=latest
NPM_CONTAINER_NAME=nginx-proxy-manager
NPM_HTTP_PORT=80
NPM_HTTPS_PORT=443
NPM_ADMIN_PORT=81
NPM_DISABLE_IPV6=true
```

#### Standalone Configuration
```bash
PROXY_TYPE=standalone
PROXY_ENABLED=false
```

### CrowdSec Configuration

```bash
# CrowdSec Collections (proxy-specific)
CROWDSEC_COLLECTIONS=crowdsecurity/linux,crowdsecurity/traefik

# Enrollment (optional)
ENROLL_INSTANCE_NAME=crowdsec-manager-traefik
ENROLL_TAGS=docker,traefik
```

## Directory Structure

After deployment, your directory structure should look like:

```
project/
├── docker-compose.yml          # Main deployment file
├── .env                        # Environment configuration
├── config/                     # Configuration files
│   ├── crowdsec/
│   │   └── acquis.yaml        # Log acquisition config
│   ├── traefik/               # Traefik configs (if using Traefik)
│   │   ├── dynamic_config.yml
│   │   └── traefik_config.yml
│   └── nginx/                 # Nginx configs (if using NPM)
├── data/                      # Persistent data
│   ├── settings.db           # CrowdSec Manager database
│   └── npm/                  # NPM data (if using NPM)
├── logs/                     # Log files
│   ├── traefik/             # Traefik logs
│   ├── nginx/               # Nginx logs
│   └── crowdsec-manager.log # Manager logs
└── backups/                 # Backup storage
```

## Service Access

After deployment, services are available at:

| Service | Default URL | Purpose |
|---------|-------------|---------|
| **CrowdSec Manager** | http://localhost:8080 | Main management interface |
| **Traefik Dashboard** | http://localhost:8081 | Traefik monitoring (if using Traefik) |
| **NPM Admin** | http://localhost:81 | NPM configuration (if using NPM) |

## Health Checks

All templates include comprehensive health checks:

```bash
# Check all service health
docker-compose ps

# Check specific service health
docker inspect --format='{{.State.Health.Status}}' crowdsec-manager

# View health check logs
docker inspect --format='{{range .State.Health.Log}}{{.Output}}{{end}}' crowdsec-manager
```

## Scaling and Performance

### Resource Requirements

| Deployment | CPU | Memory | Storage | Network |
|------------|-----|--------|---------|---------|
| **Standalone** | 1 vCPU | 1GB | 2GB | 100Mbps |
| **Single Proxy** | 2 vCPU | 2GB | 5GB | 1Gbps |
| **Full Stack** | 4 vCPU | 4GB | 10GB | 1Gbps |

### Performance Tuning

```bash
# Increase log retention for high-traffic sites
RETENTION_DAYS=90

# Adjust CrowdSec collections for your traffic
CROWDSEC_COLLECTIONS=crowdsecurity/linux,crowdsecurity/traefik,crowdsecurity/http-cve

# Enable debug logging for troubleshooting
LOG_LEVEL=debug
```

## Security Considerations

### Network Security
- All services communicate via isolated Docker network
- Only necessary ports are exposed to host
- Health checks use internal network communication

### Data Security
- Database and configuration files are stored in Docker volumes
- Automatic backups with configurable retention
- Log files are rotated and compressed

### Access Control
- CrowdSec Manager requires authentication (configure in UI)
- Proxy admin interfaces should be secured with strong passwords
- Consider using HTTPS in production (configure SSL certificates)

## Troubleshooting

### Common Issues

1. **Port Conflicts**
   ```bash
   # Check for port conflicts
   netstat -tulpn | grep :8080
   
   # Use different ports
   MANAGER_PORT=8081
   ```

2. **Permission Issues**
   ```bash
   # Fix file permissions
   sudo chown -R $USER:$USER config/ data/ logs/ backups/
   chmod -R 755 config/ data/ logs/ backups/
   ```

3. **Service Health Failures**
   ```bash
   # Check service logs
   docker-compose logs crowdsec-manager
   docker-compose logs crowdsec
   
   # Restart unhealthy services
   docker-compose restart crowdsec-manager
   ```

4. **Network Issues**
   ```bash
   # Recreate network
   docker-compose down
   docker network prune
   docker-compose up -d
   ```

### Log Analysis

```bash
# View real-time logs
docker-compose logs -f

# Search for errors
docker-compose logs | grep -i error

# Check specific timeframe
docker-compose logs --since="2024-01-01T00:00:00" --until="2024-01-01T23:59:59"
```

### Backup and Recovery

```bash
# Create manual backup
docker-compose exec crowdsec-manager curl -X POST http://localhost:8080/api/backup

# List available backups
ls -la backups/

# Restore from backup (stop services first)
docker-compose down
# Restore files manually or use backup restore API
docker-compose up -d
```

## Migration from Legacy

If migrating from a legacy Traefik-only setup:

1. **Backup Current Setup**
   ```bash
   cp docker-compose.yml docker-compose.yml.backup
   cp .env .env.backup
   ```

2. **Update Configuration**
   ```bash
   # Use Traefik template
   cp deployment-templates/docker-compose.traefik.yml docker-compose.yml
   
   # Update environment variables
   echo "PROXY_TYPE=traefik" >> .env
   ```

3. **Deploy Updated Stack**
   ```bash
   docker-compose up -d
   ```

The system will automatically detect and migrate your existing configuration.

## Support

For additional help:
- Check the main [DEPLOYMENT.md](../DEPLOYMENT.md) guide
- Review [MIGRATION.md](../MIGRATION.md) for upgrade instructions
- See [TROUBLESHOOTING.md](../docs/TROUBLESHOOTING.md) for common issues
- Visit the [examples/](../examples/) directory for more configurations