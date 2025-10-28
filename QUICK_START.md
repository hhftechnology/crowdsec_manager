# Quick Start Guide

Get CrowdSec Manager up and running in 5 minutes.

## Prerequisites

- Docker & Docker Compose installed
- Git installed
- 2GB RAM minimum
- Ports 8080 and 80 available

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/crowdsec_manager.git
cd crowdsec_manager
```

### 2. Start the Application

```bash
docker-compose up -d
```

That's it! The application is now running.

## Access the Application

- **Web UI**: http://localhost:8080
- **Traefik Dashboard**: http://localhost:8081
- **Health Check**: http://localhost:8080/health

## First Steps

### 1. Check System Health

Navigate to **Dashboard** → View real-time system status

### 2. Whitelist Your IP

1. Go to **IP Management**
2. Click "Whitelist Current IP"
3. Select both CrowdSec and Traefik
4. Click "Whitelist"

### 3. Enroll with CrowdSec Console (Optional)

1. Get your enrollment key from https://app.crowdsec.net
2. Go to **Services** → **CrowdSec**
3. Click "Enroll with Console"
4. Enter your enrollment key
5. Accept the instance in your CrowdSec dashboard

### 4. Setup Automated Backups

1. Go to **Cron Jobs**
2. Click "Setup New Job"
3. Select "Daily Backup" schedule
4. Click "Create"

## Common Tasks

### View Blocked IPs

```
Dashboard → IP Management → View Decisions
```

### Unban an IP

```
IP Management → Unban IP → Enter IP → Click Unban
```

### View Logs

```
Logs → Select Service → View Logs
```

### Create Backup

```
Backup → Create Backup → Confirm
```

### Update Stack

```
Update → Enter New Tags → Update
```

## Development Mode

For development with hot reload:

```bash
# Start development environment
docker-compose -f docker-compose.dev.yml up

# Or run locally
# Backend:
go run cmd/server/main.go

# Frontend (in separate terminal):
cd web
npm install
npm run dev
```

## Configuration

### Environment Variables

Create `.env` file (optional):

```env
PORT=8080
ENVIRONMENT=production
LOG_LEVEL=info
RETENTION_DAYS=60
```

### CrowdSec Configuration

Edit `config/crowdsec/acquis.yaml`:

```yaml
filenames:
  - /var/log/traefik/access.log
labels:
  type: traefik
```

### Traefik Configuration

Edit `config/traefik/dynamic_config.yml` for middleware and routing.

## Troubleshooting

### Application Won't Start

```bash
# Check logs
docker-compose logs crowdsec-manager

# Restart services
docker-compose restart
```

### Can't Access UI

```bash
# Check if port is in use
sudo lsof -i :8080

# Check container status
docker ps
```

### Container Not Found

Ensure all services are running:

```bash
docker ps -a
docker-compose up -d pangolin gerbil crowdsec traefik
```

## Stopping the Application

```bash
# Stop all services
docker-compose down

# Stop and remove volumes (WARNING: deletes data)
docker-compose down -v
```

## Next Steps

- Read [README.md](README.md) for detailed documentation
- See [DEPLOYMENT.md](DEPLOYMENT.md) for production deployment
- Check [FUNCTIONS_MAP.md](FUNCTIONS_MAP.md) for all features

## Getting Help

- **Issues**: https://github.com/yourusername/crowdsec_manager/issues
- **Discussions**: https://github.com/yourusername/crowdsec_manager/discussions
- **Documentation**: [README.md](README.md)

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│              CrowdSec Manager UI                │
│           http://localhost:8080                 │
│                                                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ │
│  │ Dashboard  │ │ IP Mgmt    │ │  Logs      │ │
│  └────────────┘ └────────────┘ └────────────┘ │
└─────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│              Go Backend API                     │
│         43 RESTful Endpoints                    │
│                                                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ │
│  │ Handlers   │ │ Services   │ │ Docker SDK │ │
│  └────────────┘ └────────────┘ └────────────┘ │
└─────────────────────────────────────────────────┘
                      │
        ┌─────────────┼─────────────┐
        │             │             │
        ▼             ▼             ▼
┌─────────────┐ ┌─────────┐ ┌─────────────┐
│  CrowdSec   │ │ Traefik │ │  Pangolin   │
│   Engine    │ │  Proxy  │ │  + Gerbil   │
└─────────────┘ └─────────┘ └─────────────┘
```

## Feature Highlights

✅ **All 62 bash script functions** implemented
✅ **Real-time monitoring** with WebSocket
✅ **Complete backup system** with retention
✅ **Modern UI** with Shadcn components
✅ **Production-ready** Docker setup
✅ **Comprehensive documentation**

---

**Ready to go!** Start exploring the application at http://localhost:8080
