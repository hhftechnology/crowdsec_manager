# CrowdSec Manager - Multi-Proxy Deployment Guide

This guide covers deployment strategies for CrowdSec Manager with support for multiple reverse proxy types.

## Supported Proxy Types

- **Traefik** - Full feature support (whitelist, captcha, logs, bouncer)
- **Nginx Proxy Manager** - Log parsing and bouncer integration
- **Caddy** - Bouncer integration and health monitoring
- **HAProxy** - SPOA bouncer integration and health monitoring
- **Zoraxy** - Experimental support with basic health monitoring
- **Standalone** - CrowdSec only, no proxy integration

## Deployment Modes

### Single File Mode (Recommended)

Uses Docker Compose profiles to manage all services in one file.

#### Quick Start

1. Copy environment configuration:
```bash
cp .env.example .env
```

2. Configure your proxy type in `.env`:
```bash
PROXY_TYPE=traefik  # or nginx, caddy, haproxy, zoraxy, standalone
COMPOSE_MODE=single
```

3. Deploy with your chosen proxy:
```bash
# Traefik
docker-compose --profile traefik up -d

# Nginx Proxy Manager
docker-compose --profile nginx up -d

# Caddy
docker-compose --profile caddy up -d

# HAProxy
docker-compose --profile haproxy up -d

# Zoraxy (Experimental)
docker-compose --profile zoraxy up -d

# Standalone (CrowdSec only)
docker-compose up -d
```

#### Traefik with Add-ons

Deploy Traefik with Pangolin and Gerbil:
```bash
docker-compose --profile traefik --profile pangolin --profile gerbil up -d
```

### Separate File Mode

Uses separate compose files for core services and proxy services.

#### Setup

1. Configure for separate mode:
```bash
COMPOSE_MODE=separate
```

2. Deploy core services first:
```bash
docker-compose -f docker-compose.core.yml up -d
```

3. Deploy your chosen proxy:
```bash
# Traefik
docker-compose -f docker-compose.traefik.yml up -d

# Traefik with add-ons
docker-compose -f docker-compose.traefik.yml -f docker-compose.traefik-addons.yml up -d

# Nginx Proxy Manager
docker-compose -f docker-compose.nginx.yml up -d

# Caddy
docker-compose -f docker-compose.caddy.yml up -d

# HAProxy
docker-compose -f docker-compose.haproxy.yml up -d

# Zoraxy
docker-compose -f docker-compose.zoraxy.yml up -d
```

## Configuration Examples

### Traefik Configuration

```bash
# .env
PROXY_TYPE=traefik
TRAEFIK_CONTAINER_NAME=traefik
TRAEFIK_HTTP_PORT=80
TRAEFIK_HTTPS_PORT=443
TRAEFIK_DASHBOARD_PORT=8081
TRAEFIK_HOST=traefik.localhost
```

### Nginx Proxy Manager Configuration

```bash
# .env
PROXY_TYPE=nginx
NPM_CONTAINER_NAME=nginx-proxy-manager
NPM_HTTP_PORT=80
NPM_HTTPS_PORT=443
NPM_ADMIN_PORT=81
```

### Caddy Configuration

```bash
# .env
PROXY_TYPE=caddy
CADDY_CONTAINER_NAME=caddy
CADDY_HTTP_PORT=80
CADDY_HTTPS_PORT=443
CADDY_ADMIN_PORT=2019
```

### HAProxy Configuration

```bash
# .env
PROXY_TYPE=haproxy
HAPROXY_CONTAINER_NAME=haproxy
HAPROXY_HTTP_PORT=80
HAPROXY_HTTPS_PORT=443
HAPROXY_STATS_PORT=8404
```

### Standalone Configuration

```bash
# .env
PROXY_TYPE=standalone
PROXY_ENABLED=false
```

## Directory Structure

Ensure the following directories exist:

```
├── config/
│   ├── crowdsec/
│   │   └── acquis.yaml
│   ├── traefik/          # For Traefik
│   ├── caddy/            # For Caddy
│   ├── haproxy/          # For HAProxy
│   ├── zoraxy/           # For Zoraxy
│   ├── pangolin/         # For Pangolin (Traefik add-on)
│   └── gerbil/           # For Gerbil (Traefik add-on)
├── data/
├── logs/
└── backups/
```

## Migration from Legacy Traefik Setup

Existing Traefik installations are automatically detected and migrated:

1. Legacy environment variables are mapped to new proxy settings
2. Database schema is updated with proxy configuration
3. All existing functionality is preserved
4. API backward compatibility is maintained

## Health Checks

All services include health checks:

- **CrowdSec**: `cscli capi status`
- **Traefik**: API endpoint check
- **Nginx PM**: Admin API check
- **Caddy**: Admin API check
- **HAProxy**: Stats endpoint check
- **Zoraxy**: Info API check

## Troubleshooting

### Common Issues

1. **Port Conflicts**: Ensure no other services are using the configured ports
2. **Permission Issues**: Check file permissions for config and data directories
3. **Network Issues**: Verify Docker network configuration
4. **Health Check Failures**: Check service logs for specific error messages

### Logs

View service logs:
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f crowdsec-manager
docker-compose logs -f traefik
```

### Reset Configuration

To reset to default configuration:
```bash
docker-compose down -v
rm -rf data/ logs/
docker-compose --profile <your-proxy> up -d
```

## Security Considerations

1. **API Security**: Disable insecure API access in production
2. **Network Isolation**: Use proper Docker network configuration
3. **File Permissions**: Ensure proper ownership of config files
4. **SSL/TLS**: Configure HTTPS for production deployments
5. **Backup Strategy**: Regular backups of configuration and data

## Performance Tuning

1. **Resource Limits**: Set appropriate CPU and memory limits
2. **Log Rotation**: Configure log rotation to prevent disk space issues
3. **Health Check Intervals**: Adjust health check frequency based on needs
4. **Volume Optimization**: Use appropriate volume drivers for performance

## Support

For issues and questions:
1. Check the logs for error messages
2. Verify configuration against examples
3. Ensure all required directories exist
4. Check Docker and Docker Compose versions
5. Review the troubleshooting section above