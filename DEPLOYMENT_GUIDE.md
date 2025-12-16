# CrowdSec Manager v2.0.0 - Complete Deployment Guide

## Overview

CrowdSec Manager v2.0.0 introduces multi-proxy architecture support, allowing deployment with six different reverse proxy types while maintaining 100% backward compatibility with existing Traefik installations.

## Supported Proxy Types

| Proxy Type | Features | Complexity | Best For |
|------------|----------|------------|----------|
| **Traefik** | Full feature set | Medium | Docker environments, automatic SSL |
| **Nginx Proxy Manager** | Log parsing, bouncer | Low | User-friendly web UI management |
| **Caddy** | Bouncer, health monitoring | Low | Simple setups, automatic HTTPS |
| **HAProxy** | Bouncer, health monitoring | High | High-performance load balancing |
| **Zoraxy** | Basic health monitoring | Low | Experimental, lightweight proxy |
| **Standalone** | CrowdSec core only | Minimal | API-only, external proxy setups |

## Quick Start

### 1. Choose Your Deployment Method

#### Option A: Use Deployment Templates (Recommended)
```bash
# Clone or download deployment templates
git clone https://github.com/crowdsec-manager/crowdsec-manager.git
cd crowdsec-manager

# Choose your proxy type
cp deployment-templates/docker-compose.traefik.yml docker-compose.yml
cp examples/traefik/.env .env
```

#### Option B: Use Profile-Based Deployment
```bash
# Use the main docker-compose.yml with profiles
docker-compose --profile traefik up -d
```

### 2. Configure Environment Variables

Edit the `.env` file for your chosen proxy type:

```bash
# Core configuration
PROXY_TYPE=traefik                    # Your chosen proxy type
ENVIRONMENT=production                # production|development
LOG_LEVEL=info                       # debug|info|warn|error

# Network configuration
MANAGER_PORT=8080                    # CrowdSec Manager port
NETWORK_NAME=crowdsec-network        # Docker network name

# Backup configuration
RETENTION_DAYS=60                    # Backup retention period
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

## Detailed Deployment Instructions

### Traefik Deployment

**Features**: Whitelist management, Captcha protection, Log parsing, Bouncer integration, Health monitoring, Add-ons (Pangolin/Gerbil)

#### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+
- Ports 80, 443, 8080, 8081 available

#### Configuration
```bash
# Copy Traefik template
cp deployment-templates/docker-compose.traefik.yml docker-compose.yml
cp examples/traefik/.env .env

# Edit configuration
nano .env
```

Key Traefik settings:
```bash
PROXY_TYPE=traefik
TRAEFIK_VERSION=latest
TRAEFIK_CONTAINER_NAME=traefik
TRAEFIK_HTTP_PORT=80
TRAEFIK_HTTPS_PORT=443
TRAEFIK_DASHBOARD_PORT=8081
TRAEFIK_API_INSECURE=true
```

#### Deployment
```bash
# Deploy Traefik stack
docker-compose up -d

# Deploy with Pangolin add-on
docker-compose --profile traefik --profile pangolin up -d

# Deploy with all add-ons
docker-compose --profile traefik --profile pangolin --profile gerbil up -d
```

#### Access Points
- CrowdSec Manager: http://localhost:8080
- Traefik Dashboard: http://localhost:8081

### Nginx Proxy Manager Deployment

**Features**: Log parsing, Bouncer integration, Health monitoring

#### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+
- Ports 80, 443, 81, 8080 available

#### Configuration
```bash
# Copy NPM template
cp deployment-templates/docker-compose.nginx.yml docker-compose.yml
cp examples/nginx/.env .env

# Edit configuration
nano .env
```

Key NPM settings:
```bash
PROXY_TYPE=nginx
NPM_VERSION=latest
NPM_CONTAINER_NAME=nginx-proxy-manager
NPM_HTTP_PORT=80
NPM_HTTPS_PORT=443
NPM_ADMIN_PORT=81
```

#### Deployment
```bash
# Deploy NPM stack
docker-compose up -d

# Wait for services to be healthy
docker-compose ps
```

#### Access Points
- CrowdSec Manager: http://localhost:8080
- NPM Admin Panel: http://localhost:81
  - Default credentials: admin@example.com / changeme

#### Post-Deployment Setup
1. Access NPM admin panel
2. Change default credentials
3. Configure proxy hosts
4. Set up SSL certificates
5. Configure CrowdSec bouncer (manual step)

### Caddy Deployment

**Features**: Bouncer integration, Health monitoring, Automatic HTTPS

#### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+
- Ports 80, 443, 2019, 8080 available

#### Configuration
```bash
# Copy Caddy template
cp deployment-templates/docker-compose.caddy.yml docker-compose.yml
cp examples/caddy/.env .env

# Create Caddyfile
mkdir -p config/caddy
cat > config/caddy/Caddyfile << 'EOF'
{
    order crowdsec first
}

# CrowdSec Manager
manager.localhost {
    crowdsec {
        api_url http://crowdsec:8080
        api_key {env.CROWDSEC_BOUNCER_API_KEY}
    }
    reverse_proxy crowdsec-manager:8080
}

# Example application
app.localhost {
    crowdsec {
        api_url http://crowdsec:8080
        api_key {env.CROWDSEC_BOUNCER_API_KEY}
    }
    reverse_proxy your-app:3000
}
EOF
```

#### Deployment
```bash
# Generate CrowdSec bouncer API key first
docker-compose up -d crowdsec
docker-compose exec crowdsec cscli bouncers add caddy-bouncer

# Add the API key to .env file
echo "CROWDSEC_BOUNCER_API_KEY=your-generated-key" >> .env

# Deploy full stack
docker-compose up -d
```

#### Access Points
- CrowdSec Manager: https://manager.localhost
- Caddy Admin API: http://localhost:2019

### HAProxy Deployment

**Features**: Bouncer integration (SPOA), Health monitoring, High performance

#### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+
- Ports 80, 443, 8404, 8080 available

#### Configuration
```bash
# Copy HAProxy template
cp deployment-templates/docker-compose.haproxy.yml docker-compose.yml
cp examples/haproxy/.env .env

# Create HAProxy configuration
mkdir -p config/haproxy
cat > config/haproxy/haproxy.cfg << 'EOF'
global
    daemon
    log stdout local0
    stats socket /var/run/haproxy/admin.sock mode 660 level admin
    
defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    log global
    option httplog

# CrowdSec SPOA configuration
backend crowdsec-spoa
    mode tcp
    server crowdsec-spoa crowdsec-haproxy-bouncer:9000

# Stats page
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 30s

# Frontend configuration
frontend web
    bind *:80
    bind *:443
    
    # CrowdSec filter
    filter spoe engine crowdsec config /etc/haproxy/spoe-crowdsec.conf
    http-request deny if { var(txn.crowdsec.blocked) -m bool }
    
    # Route to backends
    use_backend crowdsec-manager if { hdr(host) -i manager.localhost }
    default_backend default-app

# Backends
backend crowdsec-manager
    server manager crowdsec-manager:8080 check

backend default-app
    server app1 your-app:3000 check
EOF
```

#### Deployment
```bash
# Generate CrowdSec bouncer API key
docker-compose up -d crowdsec
docker-compose exec crowdsec cscli bouncers add haproxy-bouncer

# Add the API key to .env file
echo "CROWDSEC_BOUNCER_API_KEY=your-generated-key" >> .env

# Deploy full stack
docker-compose up -d
```

#### Access Points
- CrowdSec Manager: http://manager.localhost
- HAProxy Stats: http://localhost:8404/stats

### Standalone Deployment

**Features**: CrowdSec core functionality only, Health monitoring

#### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+
- Port 8080 available

#### Configuration
```bash
# Copy standalone template
cp deployment-templates/docker-compose.standalone.yml docker-compose.yml
cp examples/standalone/.env .env

# Edit configuration
nano .env
```

Key standalone settings:
```bash
PROXY_TYPE=standalone
PROXY_ENABLED=false
```

#### Deployment
```bash
# Deploy standalone stack
docker-compose up -d

# Check services
docker-compose ps
```

#### Access Points
- CrowdSec Manager: http://localhost:8080

## Migration from Legacy Installations

### Automatic Migration (Traefik Users)

Existing Traefik installations are automatically migrated:

```bash
# Backup current setup
cp docker-compose.yml docker-compose.yml.backup
cp .env .env.backup

# Update to v2.0.0
git pull origin main
# or download latest docker-compose.yml

# Deploy (automatic migration)
docker-compose up -d
```

The system will:
1. Detect existing Traefik configuration
2. Migrate database schema automatically
3. Map legacy environment variables
4. Preserve all existing functionality

### Manual Migration (Other Setups)

For custom or non-standard setups:

1. **Backup Everything**
   ```bash
   tar -czf backup-$(date +%Y%m%d).tar.gz config/ data/ logs/ docker-compose.yml .env
   ```

2. **Choose New Proxy Type**
   ```bash
   # Select appropriate template
   cp deployment-templates/docker-compose.nginx.yml docker-compose.yml
   ```

3. **Update Configuration**
   ```bash
   # Update .env file with new proxy settings
   echo "PROXY_TYPE=nginx" >> .env
   ```

4. **Deploy and Verify**
   ```bash
   docker-compose up -d
   # Check logs for any issues
   docker-compose logs -f crowdsec-manager
   ```

## Advanced Configuration

### SSL/TLS Configuration

#### Traefik with Let's Encrypt
```yaml
# Add to traefik service in docker-compose.yml
command:
  - "--certificatesresolvers.letsencrypt.acme.email=your-email@domain.com"
  - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
  - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"

labels:
  - "traefik.http.routers.crowdsec-manager.tls.certresolver=letsencrypt"
```

#### Nginx Proxy Manager SSL
1. Access NPM admin panel
2. Go to SSL Certificates
3. Add Let's Encrypt certificate
4. Apply to proxy hosts

### Custom Domain Configuration

Update your `.env` file:
```bash
MANAGER_HOST=manager.yourdomain.com
TRAEFIK_HOST=traefik.yourdomain.com
```

Configure DNS records:
```
manager.yourdomain.com  A  your-server-ip
traefik.yourdomain.com  A  your-server-ip
```

### High Availability Setup

#### Database Backup Strategy
```bash
# Automated backups
RETENTION_DAYS=90
BACKUP_SCHEDULE="0 2 * * *"  # Daily at 2 AM

# External backup storage
BACKUP_S3_BUCKET=your-backup-bucket
BACKUP_S3_REGION=us-east-1
```

#### Load Balancing (HAProxy)
```bash
# Multiple backend servers
backend crowdsec-manager
    balance roundrobin
    server manager1 manager1:8080 check
    server manager2 manager2:8080 check backup
```

### Monitoring and Alerting

#### Prometheus Integration
```yaml
# Add to docker-compose.yml
prometheus:
  image: prom/prometheus:latest
  ports:
    - "9090:9090"
  volumes:
    - ./config/prometheus:/etc/prometheus
```

#### Grafana Dashboard
```yaml
grafana:
  image: grafana/grafana:latest
  ports:
    - "3000:3000"
  environment:
    - GF_SECURITY_ADMIN_PASSWORD=admin
```

## Security Best Practices

### Network Security
1. **Use Docker Networks**: Isolate services using Docker networks
2. **Firewall Configuration**: Only expose necessary ports
3. **VPN Access**: Consider VPN for admin access

### Authentication
1. **Change Default Passwords**: Update all default credentials
2. **Enable 2FA**: Where supported by proxy admin interfaces
3. **API Key Rotation**: Regularly rotate CrowdSec API keys

### Data Protection
1. **Encrypt Backups**: Use encrypted backup storage
2. **Secure Logs**: Protect log files with appropriate permissions
3. **Regular Updates**: Keep all components updated

## Troubleshooting

### Common Issues

#### Port Conflicts
```bash
# Check port usage
netstat -tulpn | grep :8080

# Use alternative ports
MANAGER_PORT=8081
TRAEFIK_DASHBOARD_PORT=8082
```

#### Permission Issues
```bash
# Fix file permissions
sudo chown -R $USER:docker config/ data/ logs/
chmod -R 755 config/ data/ logs/
```

#### Service Health Failures
```bash
# Check service logs
docker-compose logs service-name

# Restart specific service
docker-compose restart service-name

# Full restart
docker-compose down && docker-compose up -d
```

#### Network Connectivity
```bash
# Test internal connectivity
docker-compose exec crowdsec-manager curl http://crowdsec:8080/health

# Check network configuration
docker network inspect crowdsec-network
```

### Log Analysis

#### CrowdSec Manager Logs
```bash
# Real-time logs
docker-compose logs -f crowdsec-manager

# Search for errors
docker-compose logs crowdsec-manager | grep -i error

# Specific time range
docker-compose logs --since="1h" crowdsec-manager
```

#### Proxy-Specific Logs
```bash
# Traefik logs
docker-compose logs traefik

# Nginx PM logs
docker-compose exec nginx-proxy-manager tail -f /data/logs/proxy-host-*.log

# Caddy logs
docker-compose logs caddy

# HAProxy logs
docker-compose logs haproxy
```

### Performance Tuning

#### Resource Limits
```yaml
# Add to service definitions
deploy:
  resources:
    limits:
      cpus: '2.0'
      memory: 2G
    reservations:
      cpus: '1.0'
      memory: 1G
```

#### Database Optimization
```bash
# SQLite optimization
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=10000;
```

## Support and Documentation

### Additional Resources
- **Main Documentation**: [README.md](README.md)
- **Migration Guide**: [MIGRATION.md](MIGRATION.md)
- **API Documentation**: [docs/API.md](docs/API.md)
- **Troubleshooting**: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)

### Community Support
- **GitHub Issues**: Report bugs and feature requests
- **GitHub Discussions**: Community support and questions
- **Documentation**: Comprehensive guides and examples

### Professional Support
For enterprise deployments and professional support, contact the CrowdSec Manager team.

---

**Note**: This deployment guide covers CrowdSec Manager v2.0.0. Always refer to the latest documentation for the most current information.