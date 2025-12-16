# CrowdSec Manager - Deployment Examples

This directory contains example configurations for deploying CrowdSec Manager with different reverse proxy types and deployment strategies.

## Available Examples

### Single File Mode (Recommended)

Uses Docker Compose profiles to manage all services in one file.

- **[traefik/](traefik/)** - Basic Traefik deployment
- **[traefik-with-addons/](traefik-with-addons/)** - Traefik with Pangolin and Gerbil add-ons
- **[nginx/](nginx/)** - Nginx Proxy Manager deployment
- **[caddy/](caddy/)** - Caddy reverse proxy deployment
- **[haproxy/](haproxy/)** - HAProxy load balancer deployment
- **[zoraxy/](zoraxy/)** - Zoraxy reverse proxy deployment (experimental)
- **[standalone/](standalone/)** - CrowdSec only, no reverse proxy

### Separate File Mode

Uses separate compose files for core services and proxy services.

- **[separate-mode/traefik/](separate-mode/traefik/)** - Traefik with separate files
- **[separate-mode/nginx/](separate-mode/nginx/)** - Nginx PM with separate files

## Quick Start

1. Choose your deployment example
2. Copy the `.env` file to your project root
3. Customize the configuration as needed
4. Run the deployment commands

### Example: Traefik Deployment

```bash
# Copy configuration
cp examples/traefik/.env .env

# Deploy with Traefik
docker-compose --profile traefik up -d

# Or with add-ons
docker-compose --profile traefik --profile pangolin --profile gerbil up -d
```

### Example: Nginx Proxy Manager

```bash
# Copy configuration
cp examples/nginx/.env .env

# Deploy with Nginx PM
docker-compose --profile nginx up -d
```

### Example: Separate Mode

```bash
# Copy configuration
cp examples/separate-mode/traefik/.env .env

# Deploy core services first
docker-compose -f docker-compose.core.yml up -d

# Deploy Traefik
docker-compose -f docker-compose.traefik.yml up -d
```

## Proxy Feature Comparison

| Proxy Type | Whitelist | Captcha | Log Parsing | Bouncer | Health Check |
|------------|-----------|---------|-------------|---------|--------------|
| Traefik    | ✅        | ✅      | ✅          | ✅      | ✅           |
| Nginx PM   | ❌        | ❌      | ✅          | ✅      | ✅           |
| Caddy      | ❌        | ❌      | ❌          | ✅      | ✅           |
| HAProxy    | ❌        | ❌      | ❌          | ✅      | ✅           |
| Zoraxy     | ❌        | ❌      | ❌          | ⚠️      | ✅           |
| Standalone | ❌        | ❌      | ❌          | ❌      | ✅           |

**Legend:**
- ✅ Fully supported
- ⚠️ Experimental support
- ❌ Not supported

## Traefik Add-ons

Pangolin and Gerbil are optional add-ons available only with Traefik:

### Pangolin
- Advanced SSL/TLS management
- Certificate automation
- Security middleware
- Dynamic configuration

### Gerbil
- WireGuard VPN integration
- Network security policies
- Remote access management
- Traffic encryption

## Configuration Options

### Core Settings

```bash
COMPOSE_MODE=single          # single|separate
PROXY_TYPE=traefik          # traefik|nginx|caddy|haproxy|zoraxy|standalone
PROXY_ENABLED=true          # Enable proxy integration
ENVIRONMENT=production      # production|development
LOG_LEVEL=info             # debug|info|warn|error
```

### Proxy-Specific Settings

Each proxy type has its own configuration variables. See the individual example files for details.

### Network Configuration

```bash
NETWORK_NAME=crowdsec-network    # Docker network name
MANAGER_PORT=8080               # CrowdSec Manager port
RETENTION_DAYS=60               # Backup retention period
```

## Migration from Legacy Traefik

Existing Traefik installations are automatically detected and migrated:

1. Legacy environment variables are mapped to new proxy settings
2. Database schema is updated with proxy configuration
3. All existing functionality is preserved
4. API backward compatibility is maintained

Simply update your docker-compose.yml and restart services.

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

## Support

For additional help:
1. Check the main [DEPLOYMENT.md](../DEPLOYMENT.md) guide
2. Review the troubleshooting section
3. Verify configuration against examples
4. Check Docker and Docker Compose versions