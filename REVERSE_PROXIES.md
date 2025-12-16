# Reverse Proxy Integration Guide

This guide provides detailed information about integrating CrowdSec Manager with different reverse proxy types. Each proxy has different capabilities and integration methods.

## Overview

CrowdSec Manager supports six deployment modes:

| Proxy Type | Whitelist | Captcha | Log Parsing | Bouncer | Health Check | Status |
|------------|-----------|---------|-------------|---------|--------------|--------|
| **Traefik** | ✅ Full | ✅ Cloudflare Turnstile | ✅ Advanced | ✅ Plugin | ✅ Comprehensive | Stable |
| **Nginx Proxy Manager** | ❌ NPM Managed | ❌ NPM Managed | ✅ Log Files | ✅ cs-nginx-bouncer | ✅ Basic | Stable |
| **Caddy** | ❌ Manual | ❌ Manual | ❌ Basic | ✅ Module | ✅ Basic | Stable |
| **HAProxy** | ❌ Manual | ❌ Manual | ❌ Basic | ✅ SPOA | ✅ Basic | Stable |
| **Zoraxy** | ❌ Manual | ❌ Manual | ❌ Basic | ⚠️ Experimental | ✅ Basic | Experimental |
| **Standalone** | N/A | N/A | N/A | N/A | ✅ CrowdSec Only | Stable |

## Traefik Integration

### Overview
Traefik provides the most comprehensive integration with full support for all CrowdSec Manager features.

### Features Supported
- ✅ **Whitelist Management**: Dynamic configuration YAML manipulation
- ✅ **Captcha Protection**: Cloudflare Turnstile middleware integration
- ✅ **Advanced Log Parsing**: Traefik access log analysis with statistics
- ✅ **Bouncer Integration**: crowdsec-bouncer-traefik-plugin monitoring
- ✅ **Health Monitoring**: Container status, API availability, configuration validation
- ✅ **Add-on Services**: Pangolin and Gerbil integration

### Configuration

#### Environment Variables
```bash
PROXY_TYPE=traefik
TRAEFIK_CONTAINER_NAME=traefik
TRAEFIK_DYNAMIC_CONFIG=/etc/traefik/dynamic_config.yml
TRAEFIK_STATIC_CONFIG=/etc/traefik/traefik_config.yml
TRAEFIK_ACCESS_LOG=/var/log/traefik/access.log
TRAEFIK_ERROR_LOG=/var/log/traefik/traefik.log
```

#### Docker Compose Profile
```bash
# Single file mode
docker-compose --profile traefik up -d

# With add-ons
docker-compose --profile traefik --profile pangolin --profile gerbil up -d

# Separate files mode
docker-compose -f docker-compose.core.yml up -d
docker-compose -f docker-compose.traefik.yml up -d
```

#### Required Directory Structure
```
config/
├── traefik/
│   ├── dynamic_config.yml    # Dynamic routing and middleware
│   ├── traefik_config.yml    # Static configuration
│   └── logs/                 # Access and error logs
└── crowdsec/
    └── acquis.yaml           # Log acquisition config
```

#### Sample Traefik Configuration

**traefik_config.yml** (Static):
```yaml
api:
  dashboard: true
  insecure: true

entryPoints:
  web:
    address: ":80"
  websecure:
    address: ":443"

providers:
  docker:
    exposedByDefault: false
  file:
    directory: /etc/traefik
    watch: true

accessLog:
  filePath: "/var/log/traefik/access.log"

log:
  level: INFO
  filePath: "/var/log/traefik/traefik.log"
```

**dynamic_config.yml** (Dynamic):
```yaml
http:
  middlewares:
    crowdsec-bouncer:
      plugin:
        bouncer:
          enabled: true
          logLevel: INFO
          crowdsecMode: live
          crowdsecAppsecEnabled: false
          crowdsecAppsecHost: crowdsec:7422
          crowdsecLapiKey: your-lapi-key
          crowdsecLapiKeyFile: /etc/traefik/lapi-key
          crowdsecLapiHost: crowdsec:8080
          crowdsecLapiScheme: http
          crowdsecCapiMachineId: your-machine-id
          crowdsecCapiPassword: your-capi-password
          crowdsecCapiScenarios:
            - crowdsecurity/http-path-traversal-probing
            - crowdsecurity/http-xss-probing
            - crowdsecurity/http-generic-bf

    # Whitelist middleware (managed by CrowdSec Manager)
    crowdsec-whitelist:
      ipWhiteList:
        sourceRange:
          - "127.0.0.1/32"
          - "10.0.0.0/8"
          - "172.16.0.0/12"
          - "192.168.0.0/16"

  routers:
    api:
      rule: "Host(`traefik.localhost`)"
      service: "api@internal"
      middlewares:
        - "crowdsec-bouncer"
        - "crowdsec-whitelist"
```

#### CrowdSec Acquisition Configuration

**acquis.yaml**:
```yaml
filenames:
  - /var/log/traefik/access.log
labels:
  type: traefik
---
source: docker
container_name:
  - traefik
labels:
  type: traefik
```

### Bouncer Setup

1. **Install the Traefik Plugin**:
   ```yaml
   # In traefik_config.yml
   experimental:
     plugins:
       bouncer:
         moduleName: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin
         version: v1.1.13
   ```

2. **Generate LAPI Key**:
   ```bash
   docker exec crowdsec cscli bouncers add traefik-bouncer
   ```

3. **Configure the Plugin** in dynamic_config.yml (see example above)

### API Endpoints

All standard CrowdSec Manager API endpoints are available with full functionality:

```bash
# Whitelist management
POST /api/whitelist/current
POST /api/whitelist/manual
POST /api/whitelist/cidr

# Captcha configuration
POST /api/captcha/setup
GET /api/captcha/status

# Advanced log analysis
GET /api/logs/traefik/advanced
```

## Nginx Proxy Manager Integration

### Overview
Nginx Proxy Manager integration focuses on log parsing and bouncer monitoring, with NPM handling whitelist and captcha management through its own interface.

### Features Supported
- ❌ **Whitelist Management**: Managed through NPM interface
- ❌ **Captcha Protection**: Managed through NPM interface
- ✅ **Log Parsing**: NPM access log analysis
- ✅ **Bouncer Integration**: cs-nginx-bouncer monitoring
- ✅ **Health Monitoring**: Container status and API availability

### Configuration

#### Environment Variables
```bash
PROXY_TYPE=nginx
NPM_CONTAINER_NAME=nginx-proxy-manager
NPM_HTTP_PORT=80
NPM_HTTPS_PORT=443
NPM_ADMIN_PORT=81
```

#### Docker Compose Profile
```bash
# Single file mode
docker-compose --profile nginx up -d

# Separate files mode
docker-compose -f docker-compose.core.yml up -d
docker-compose -f docker-compose.nginx.yml up -d
```

#### Required Directory Structure
```
config/
├── letsencrypt/              # SSL certificates
└── crowdsec/
    └── acquis.yaml           # Log acquisition config
data/
└── npm/                      # NPM database and config
logs/
└── nginx/                    # NPM access logs
```

#### CrowdSec Acquisition Configuration

**acquis.yaml**:
```yaml
filenames:
  - /data/logs/proxy-host-*.log
labels:
  type: nginx
---
source: docker
container_name:
  - nginx-proxy-manager
labels:
  type: nginx
```

### Bouncer Setup

1. **Install cs-nginx-bouncer** in the NPM container:
   ```bash
   # This typically requires a custom NPM image with the bouncer pre-installed
   # Or manual installation in the running container
   docker exec nginx-proxy-manager apt-get update
   docker exec nginx-proxy-manager apt-get install crowdsec-nginx-bouncer
   ```

2. **Configure the bouncer**:
   ```bash
   # Generate LAPI key
   docker exec crowdsec cscli bouncers add nginx-bouncer
   
   # Configure bouncer (in NPM container)
   docker exec nginx-proxy-manager crowdsec-nginx-bouncer-config
   ```

### API Endpoints

Limited API functionality compared to Traefik:

```bash
# Log parsing (available)
GET /api/logs/nginx
GET /api/logs/proxy

# Whitelist management (returns not supported)
POST /api/whitelist/current  # Returns error with NPM management instructions

# Bouncer status (available)
GET /api/bouncer/nginx
```

### NPM-Specific Notes

- **Whitelist Management**: Use NPM's Access Lists feature
- **SSL/TLS**: Managed through NPM's SSL certificate interface
- **Custom Locations**: Configure custom locations in NPM for CrowdSec integration
- **Log Format**: NPM uses standard Nginx log format, parsed by CrowdSec Manager

## Caddy Integration

### Overview
Caddy integration provides bouncer functionality through the CrowdSec bouncer module with basic health monitoring.

### Features Supported
- ❌ **Whitelist Management**: Configure manually in Caddyfile
- ❌ **Captcha Protection**: Configure manually in Caddyfile
- ❌ **Advanced Log Parsing**: Basic log access only
- ✅ **Bouncer Integration**: caddy-crowdsec-bouncer module
- ✅ **Health Monitoring**: Container status and admin API

### Configuration

#### Environment Variables
```bash
PROXY_TYPE=caddy
CADDY_CONTAINER_NAME=caddy
CADDY_HTTP_PORT=80
CADDY_HTTPS_PORT=443
CADDY_ADMIN_PORT=2019
```

#### Docker Compose Profile
```bash
# Single file mode
docker-compose --profile caddy up -d

# Separate files mode
docker-compose -f docker-compose.core.yml up -d
docker-compose -f docker-compose.caddy.yml up -d
```

#### Required Directory Structure
```
config/
├── caddy/
│   └── Caddyfile             # Caddy configuration
└── crowdsec/
    └── acquis.yaml           # Log acquisition config
data/
└── caddy/                    # Caddy data directory
logs/
└── caddy/                    # Caddy logs
```

#### Sample Caddyfile

```caddyfile
{
    # Global options
    admin 0.0.0.0:2019
    
    # CrowdSec bouncer module
    order crowdsec first
    
    # Logging
    log {
        output file /var/log/caddy/access.log
        format json
    }
}

# Example site with CrowdSec protection
example.com {
    # CrowdSec bouncer
    crowdsec {
        api_url http://crowdsec:8080
        api_key {env.CROWDSEC_BOUNCER_API_KEY}
        ticker_interval 60s
    }
    
    # Your site configuration
    reverse_proxy backend:8080
    
    # Manual whitelist (if needed)
    @whitelist {
        remote_ip 192.168.1.0/24 10.0.0.0/8
    }
    handle @whitelist {
        reverse_proxy backend:8080
    }
}
```

#### CrowdSec Acquisition Configuration

**acquis.yaml**:
```yaml
filenames:
  - /var/log/caddy/access.log
labels:
  type: caddy
---
source: docker
container_name:
  - caddy
labels:
  type: caddy
```

### Bouncer Setup

1. **Use Caddy with CrowdSec Module**:
   ```dockerfile
   # Custom Caddy build with CrowdSec module
   FROM caddy:builder AS builder
   RUN xcaddy build --with github.com/hslatman/caddy-crowdsec-bouncer/http
   
   FROM caddy:latest
   COPY --from=builder /usr/bin/caddy /usr/bin/caddy
   ```

2. **Generate LAPI Key**:
   ```bash
   docker exec crowdsec cscli bouncers add caddy-bouncer
   export CROWDSEC_BOUNCER_API_KEY=your-generated-key
   ```

### API Endpoints

Limited API functionality:

```bash
# Basic log access
GET /api/logs/caddy

# Bouncer status
GET /api/bouncer/caddy

# Health monitoring
GET /api/health/proxy
```

## HAProxy Integration

### Overview
HAProxy integration uses the SPOA (Stream Processing Offload API) bouncer for CrowdSec integration.

### Features Supported
- ❌ **Whitelist Management**: Configure manually in haproxy.cfg
- ❌ **Captcha Protection**: Not supported
- ❌ **Advanced Log Parsing**: Basic log access only
- ✅ **Bouncer Integration**: cs-haproxy-bouncer SPOA
- ✅ **Health Monitoring**: Stats page and container status

### Configuration

#### Environment Variables
```bash
PROXY_TYPE=haproxy
HAPROXY_CONTAINER_NAME=haproxy
HAPROXY_HTTP_PORT=80
HAPROXY_HTTPS_PORT=443
HAPROXY_STATS_PORT=8404
```

#### Docker Compose Profile
```bash
# Single file mode
docker-compose --profile haproxy up -d

# Separate files mode
docker-compose -f docker-compose.core.yml up -d
docker-compose -f docker-compose.haproxy.yml up -d
```

#### Required Directory Structure
```
config/
├── haproxy/
│   ├── haproxy.cfg           # HAProxy configuration
│   └── certs/                # SSL certificates
└── crowdsec/
    └── acquis.yaml           # Log acquisition config
logs/
└── haproxy/                  # HAProxy logs
```

#### Sample HAProxy Configuration

**haproxy.cfg**:
```haproxy
global
    daemon
    log stdout local0
    
    # SPOA configuration for CrowdSec
    stats socket /var/run/haproxy.sock mode 600 level admin
    stats timeout 30s

defaults
    mode http
    log global
    option httplog
    option dontlognull
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

# Stats page
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 30s

# CrowdSec SPOA backend
backend crowdsec-spoa
    mode tcp
    server crowdsec-bouncer crowdsec-bouncer:9000 check

# Frontend with CrowdSec protection
frontend web
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/
    
    # SPOA filter for CrowdSec
    filter spoe engine crowdsec config /etc/haproxy/spoe-crowdsec.conf
    
    # Default backend
    default_backend webservers

# Backend servers
backend webservers
    balance roundrobin
    server web1 backend1:80 check
    server web2 backend2:80 check
```

**spoe-crowdsec.conf**:
```
[crowdsec]
spoe-agent crowdsec-agent
    messages check-ip
    option var-prefix crowdsec
    timeout hello 2s
    timeout idle 2m
    timeout processing 10ms
    use-backend crowdsec-spoa

spoe-message check-ip
    args ip=src
    event on-frontend-http-request
```

### Bouncer Setup

1. **Deploy cs-haproxy-bouncer**:
   ```yaml
   # Add to docker-compose.yml
   crowdsec-bouncer-haproxy:
     image: crowdsecurity/cs-haproxy-bouncer:latest
     container_name: crowdsec-bouncer-haproxy
     environment:
       - CROWDSEC_BOUNCER_API_KEY=your-api-key
       - CROWDSEC_AGENT_HOST=crowdsec
       - CROWDSEC_AGENT_PORT=8080
     networks:
       - crowdsec-network
   ```

2. **Generate LAPI Key**:
   ```bash
   docker exec crowdsec cscli bouncers add haproxy-bouncer
   ```

### API Endpoints

Limited API functionality:

```bash
# Basic log access
GET /api/logs/haproxy

# Bouncer status
GET /api/bouncer/haproxy

# Health monitoring (stats page)
GET /api/health/proxy
```

## Zoraxy Integration (Experimental)

### Overview
Zoraxy integration is experimental with basic health monitoring and limited CrowdSec integration.

### Features Supported
- ❌ **Whitelist Management**: Configure manually in Zoraxy
- ❌ **Captcha Protection**: Not supported
- ❌ **Advanced Log Parsing**: Basic log access only
- ⚠️ **Bouncer Integration**: Experimental
- ✅ **Health Monitoring**: Basic container status

### Configuration

#### Environment Variables
```bash
PROXY_TYPE=zoraxy
ZORAXY_CONTAINER_NAME=zoraxy
ZORAXY_HTTP_PORT=80
ZORAXY_HTTPS_PORT=443
ZORAXY_ADMIN_PORT=8000
```

#### Docker Compose Profile
```bash
# Single file mode
docker-compose --profile zoraxy up -d
```

### API Endpoints

Very limited functionality:

```bash
# Basic health monitoring
GET /api/health/proxy

# Basic log access
GET /api/logs/zoraxy
```

## Standalone Mode

### Overview
Standalone mode runs CrowdSec Manager without any reverse proxy integration, providing core CrowdSec management features only.

### Features Supported
- N/A **Whitelist Management**: CrowdSec allowlists only
- N/A **Captcha Protection**: Not applicable
- N/A **Log Parsing**: CrowdSec logs only
- N/A **Bouncer Integration**: Not applicable
- ✅ **Health Monitoring**: CrowdSec core components only

### Configuration

#### Environment Variables
```bash
PROXY_TYPE=standalone
PROXY_ENABLED=false
```

#### Docker Compose
```bash
# Single file mode (no proxy profile)
docker-compose up -d

# Separate files mode (core only)
docker-compose -f docker-compose.core.yml up -d
```

### Use Cases

- **API-only deployments**: When using CrowdSec with external integrations
- **Development/testing**: Testing CrowdSec functionality without proxy complexity
- **Custom integrations**: Building custom proxy integrations
- **Troubleshooting**: Isolating CrowdSec issues from proxy configuration

## API Reference

### Generic Proxy Endpoints

These endpoints work with all proxy types and return appropriate responses based on supported features:

```bash
# Get current proxy information
GET /api/proxy/current
Response: {
  "type": "traefik|nginx|caddy|haproxy|zoraxy|standalone",
  "enabled": true|false,
  "container_name": "string",
  "running": true|false,
  "supported_features": ["whitelist", "captcha", "logs", "bouncer", "health"],
  "config_files": ["path1", "path2"]
}

# Get available proxy types
GET /api/proxy/types
Response: [
  {
    "type": "traefik",
    "name": "Traefik",
    "description": "Full-featured reverse proxy with comprehensive CrowdSec integration",
    "supported_features": ["whitelist", "captcha", "logs", "bouncer", "health"],
    "status": "stable"
  },
  // ... other proxy types
]

# Get supported features for current proxy
GET /api/proxy/features
Response: {
  "whitelist": {
    "supported": true|false,
    "description": "IP whitelist management at proxy level"
  },
  "captcha": {
    "supported": true|false,
    "description": "Captcha protection middleware"
  },
  // ... other features
}
```

### Proxy-Aware Whitelist API

```bash
# Add IP to whitelist (generic)
POST /api/whitelist/manual
{
  "ip": "192.168.1.100",
  "add_to_crowdsec": true,
  "add_to_proxy": true  # Generic field
}

# Legacy format (still supported)
POST /api/whitelist/manual
{
  "ip": "192.168.1.100",
  "add_to_crowdsec": true,
  "add_to_traefik": true  # Legacy field
}

# Response includes both formats
Response: {
  "success": true,
  "ip": "192.168.1.100",
  "in_crowdsec": true,
  "in_proxy": true,     # Generic field
  "in_traefik": true,   # Legacy field (for backward compatibility)
  "proxy_support": {
    "whitelist": true|false,
    "method": "dynamic_config|not_supported|manual"
  }
}
```

### Health Monitoring API

```bash
# Comprehensive health check
GET /api/health/complete
Response: {
  "crowdsec": {
    "running": true,
    "api_available": true,
    "version": "v1.4.0"
  },
  "proxy": {
    "type": "traefik",
    "running": true,
    "api_available": true,
    "version": "v2.10.0",
    "health_checks": [
      {"name": "Container Status", "status": "healthy"},
      {"name": "API Availability", "status": "healthy"},
      {"name": "Configuration Valid", "status": "healthy"}
    ]
  },
  "bouncer": {
    "configured": true,
    "connected": true,
    "last_seen": "2023-12-15T10:30:00Z"
  }
}
```

## Troubleshooting

### Common Issues

#### Proxy Not Detected
```bash
# Check proxy type configuration
curl http://localhost:8080/api/proxy/current

# Verify container is running
docker ps | grep your-proxy-container

# Check environment variables
docker exec crowdsec-manager env | grep PROXY
```

#### Bouncer Connection Issues
```bash
# Check bouncer status
curl http://localhost:8080/api/bouncer/status

# Verify LAPI key
docker exec crowdsec cscli bouncers list

# Check network connectivity
docker exec your-proxy-container ping crowdsec
```

#### Log Parsing Not Working
```bash
# Check log file permissions
ls -la ./logs/your-proxy/

# Verify acquis.yaml configuration
docker exec crowdsec cat /etc/crowdsec/acquis.yaml

# Check CrowdSec log acquisition
docker exec crowdsec cscli metrics
```

### Proxy-Specific Troubleshooting

#### Traefik
- **Dynamic config not updating**: Check file permissions and Traefik file provider configuration
- **Plugin not loading**: Verify experimental.plugins configuration in static config
- **Whitelist not working**: Check dynamic_config.yml syntax and middleware application

#### Nginx Proxy Manager
- **Logs not parsing**: Verify NPM log format and file locations
- **Bouncer not working**: Check cs-nginx-bouncer installation and configuration

#### Caddy
- **Module not found**: Ensure Caddy is built with the CrowdSec bouncer module
- **Configuration errors**: Check Caddyfile syntax and module configuration

#### HAProxy
- **SPOA connection failed**: Verify cs-haproxy-bouncer container is running and accessible
- **Stats page not accessible**: Check HAProxy stats configuration and port binding

## Best Practices

### Security
- **Use strong LAPI keys**: Generate unique keys for each bouncer
- **Limit network access**: Use Docker networks to isolate services
- **Regular updates**: Keep proxy and bouncer components updated
- **Monitor logs**: Regularly check CrowdSec and proxy logs for issues

### Performance
- **Log rotation**: Configure log rotation to prevent disk space issues
- **Resource limits**: Set appropriate CPU and memory limits for containers
- **Health checks**: Configure proper health checks for all services
- **Monitoring**: Use monitoring tools to track performance metrics

### Maintenance
- **Backup configurations**: Regular backups of proxy and CrowdSec configurations
- **Test changes**: Test configuration changes in non-production environments
- **Documentation**: Document custom configurations and integrations
- **Version control**: Use version control for configuration files

This guide provides comprehensive information for integrating CrowdSec Manager with various reverse proxy types. Choose the proxy that best fits your infrastructure needs and follow the specific integration instructions for optimal security and performance.