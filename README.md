# CrowdSec Manager

A web-based management interface for CrowdSec security stack with Pangolin integration. This project replaces the bash script with a modern, user-friendly web UI built with Go and React.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8.svg)
![React Version](https://img.shields.io/badge/react-18.3-61DAFB.svg)

## Features

###  Complete Security Management

- **System Health Monitoring** - Real-time container status and diagnostics
- **IP Management** - Block, unban, and monitor IP addresses
- **Whitelist Management** - Comprehensive IP and CIDR whitelisting for CrowdSec and Traefik
- **Decision Management** - View and manage CrowdSec security decisions
- **Bouncer Management** - Monitor CrowdSec bouncers and their status

###  Advanced Security Features

- **Custom Scenarios** - Deploy custom CrowdSec detection scenarios
- **Captcha Protection** - Configure Cloudflare Turnstile captcha integration
- **Traefik Integration** - Seamless CrowdSec-Traefik middleware configuration
- **Console Enrollment** - Easy CrowdSec Console integration

###  Monitoring & Logs

- **Real-time Log Streaming** - WebSocket-based live log viewing
- **Advanced Log Analysis** - Analyze Traefik logs with statistics
- **Prometheus Metrics** - View CrowdSec metrics
- **Multi-service Logs** - View logs from all services (CrowdSec, Traefik, Pangolin, Gerbil)

###  Backup & Recovery

- **Automated Backups** - Create full system backups
- **Scheduled Backups** - Configure cron jobs for automatic backups
- **Easy Restoration** - Restore from any backup with confirmation
- **Retention Management** - Automatic cleanup of old backups

###  Stack Updates

- **Version Management** - Update Docker images with custom tags
- **Graceful Updates** - Safe updates with automatic rollback on failure
- **Flexible Configuration** - Update with or without CrowdSec

## Architecture

### Backend (Go)
- **Framework**: Gin HTTP router
- **Docker Integration**: Docker SDK for Go
- **Logging**: Structured logging with slog
- **Configuration**: Environment-based configuration

### Frontend (React + TypeScript)
- **UI Framework**: Shadcn/ui components
- **Styling**: Tailwind CSS
- **State Management**: TanStack Query
- **Routing**: React Router DOM
- **Real-time Updates**: WebSocket support

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Go 1.23+ (for local development)
- Node.js 20+ (for frontend development)

### Production Deployment

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/crowdsec_manager.git
   cd crowdsec_manager
   ```

2. **Configure environment** (optional)
   ```bash
   cp .env.example .env
   # Edit .env with your preferences
   ```

3. **Start the stack**
   ```bash
   docker-compose up -d
   ```

4. **Access the UI**
   - Web Interface: http://localhost:8080
   - Traefik Dashboard: http://localhost:8081
   - CrowdSec Manager: http://manager.localhost (with Traefik routing)

### Development Setup

1. **Start development environment**
   ```bash
   docker-compose -f docker-compose.dev.yml up
   ```

2. **Or run components separately**

   **Backend:**
   ```bash
   cd crowdsec_manager
   go run cmd/server/main.go
   ```

   **Frontend:**
   ```bash
   cd web
   npm install
   npm run dev
   ```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | API server port |
| `ENVIRONMENT` | `development` | Environment mode |
| `LOG_LEVEL` | `info` | Logging level (debug, info, warn, error) |
| `LOG_FILE` | `./logs/crowdsec-manager.log` | Log file path |
| `BACKUP_DIR` | `./backups` | Backup directory |
| `RETENTION_DAYS` | `60` | Backup retention period |
| `INCLUDE_CROWDSEC` | `true` | Include CrowdSec in operations |

### Directory Structure

```
crowdsec_manager/
├── cmd/
│   └── server/
│       └── main.go              # Application entry point
├── internal/
│   ├── api/
│   │   ├── handlers/            # API handlers (43 functions)
│   │   └── routes.go            # Route definitions
│   ├── backup/                  # Backup management
│   ├── config/                  # Configuration
│   ├── docker/                  # Docker client wrapper
│   ├── logger/                  # Structured logging
│   └── models/                  # Data models
├── web/
│   ├── src/
│   │   ├── components/          # React components
│   │   ├── lib/                 # API client & utilities
│   │   └── pages/               # Application pages
│   └── public/                  # Static assets
├── config/                      # Configuration files
│   ├── traefik/                 # Traefik configuration
│   └── crowdsec/                # CrowdSec configuration
├── backups/                     # Backup storage
├── logs/                        # Application logs
├── docker-compose.yml           # Production compose
├── docker-compose.dev.yml       # Development compose
├── Dockerfile                   # Production Dockerfile
└── Dockerfile.dev               # Development Dockerfile
```

## API Documentation

### All 43 Endpoints

#### Health & Diagnostics
- `GET /api/health/stack` - Check all container statuses
- `GET /api/health/complete` - Complete system diagnostics

#### IP Management
- `GET /api/ip/public` - Get current public IP
- `GET /api/ip/blocked/:ip` - Check if IP is blocked
- `GET /api/ip/security/:ip` - Comprehensive IP security check
- `POST /api/ip/unban` - Unban an IP address

#### Whitelist Management
- `GET /api/whitelist/view` - View all whitelisted IPs
- `POST /api/whitelist/current` - Whitelist current public IP
- `POST /api/whitelist/manual` - Whitelist specific IP
- `POST /api/whitelist/cidr` - Whitelist CIDR range
- `POST /api/whitelist/crowdsec` - Add to CrowdSec whitelist
- `POST /api/whitelist/traefik` - Add to Traefik whitelist
- `POST /api/whitelist/comprehensive` - Setup full whitelist

#### Scenarios
- `POST /api/scenarios/setup` - Install custom scenarios
- `GET /api/scenarios/list` - List installed scenarios

#### Captcha
- `POST /api/captcha/setup` - Configure captcha
- `GET /api/captcha/status` - Get captcha status

#### Logs
- `GET /api/logs/crowdsec` - Get CrowdSec logs
- `GET /api/logs/traefik` - Get Traefik logs
- `GET /api/logs/traefik/advanced` - Advanced log analysis
- `GET /api/logs/:service` - Get service logs
- `GET /api/logs/stream/:service` - Stream logs (WebSocket)

#### Backup
- `GET /api/backup/list` - List all backups
- `POST /api/backup/create` - Create new backup
- `POST /api/backup/restore` - Restore from backup
- `DELETE /api/backup/:id` - Delete backup
- `POST /api/backup/cleanup` - Remove old backups
- `GET /api/backup/latest` - Get latest backup

#### Update
- `GET /api/update/current-tags` - Get current image tags
- `POST /api/update/with-crowdsec` - Update with CrowdSec
- `POST /api/update/without-crowdsec` - Update without CrowdSec

#### Cron
- `POST /api/cron/setup` - Setup cron job
- `GET /api/cron/list` - List cron jobs
- `DELETE /api/cron/:id` - Delete cron job

#### Services
- `GET /api/services/verify` - Verify services status
- `POST /api/services/shutdown` - Graceful shutdown
- `POST /api/services/action` - Service action (start/stop/restart)

#### CrowdSec
- `GET /api/crowdsec/bouncers` - Get bouncers list
- `GET /api/crowdsec/decisions` - Get decisions list
- `GET /api/crowdsec/metrics` - Get Prometheus metrics
- `POST /api/crowdsec/enroll` - Enroll with Console

#### Traefik
- `GET /api/traefik/integration` - Check integration
- `GET /api/traefik/config` - Get configuration

## Usage Examples

### Whitelist Current IP
```bash
curl -X POST http://localhost:8080/api/whitelist/current \
  -H "Content-Type: application/json" \
  -d '{"add_to_crowdsec": true, "add_to_traefik": true}'
```

### Check IP Security
```bash
curl http://localhost:8080/api/ip/security/1.2.3.4
```

### Create Backup
```bash
curl -X POST http://localhost:8080/api/backup/create \
  -H "Content-Type: application/json" \
  -d '{"dry_run": false}'
```

### Get System Health
```bash
curl http://localhost:8080/api/health/stack
```

## Function Mapping

All 62 functions from the original bash script have been implemented:

- ✅ 2 Health & Diagnostics functions
- ✅ 10 IP Management functions
- ✅ 9 Whitelist Management functions
- ✅ 1 Scenario Management function
- ✅ 1 Captcha Management function
- ✅ 5 Logs & Monitoring functions
- ✅ 8 Backup functions
- ✅ 10 Update functions
- ✅ 13 Utility functions
- ✅ 3 Logging & UI functions (translated to UI components)

See [FUNCTIONS_MAP.md](FUNCTIONS_MAP.md) for detailed mapping.

## Development

### Building

**Backend:**
```bash
go build -o crowdsec-manager ./cmd/server
```

**Frontend:**
```bash
cd web
npm run build
```

**Docker:**
```bash
docker build -t crowdsec-manager:latest .
```

### Testing

**Backend:**
```bash
go test -v ./...
```

**Frontend:**
```bash
cd web
npm run lint
```

### Hot Reload

Development mode includes automatic reloading:
- Backend: Air (Go hot reload)
- Frontend: Vite (instant HMR)

## Troubleshooting

### Container Not Found
Ensure all required containers are running:
```bash
docker ps
```

### Permission Denied
The application needs access to Docker socket:
```bash
# Linux/macOS
sudo usermod -aG docker $USER

# Or run with appropriate permissions
sudo docker-compose up
```

### Port Already in Use
Change the port in docker-compose.yml or .env:
```yaml
ports:
  - "8090:8080"  # Use port 8090 instead
```

### Backup Failures
Check backup directory permissions:
```bash
chmod 755 backups/
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Original bash script by hhf-technology
- CrowdSec for the security engine
- Traefik for reverse proxy
- Shadcn/ui for UI components

## Support

- Issues: [GitHub Issues](https://github.com/yourusername/crowdsec_manager/issues)
- Discussions: [GitHub Discussions](https://github.com/yourusername/crowdsec_manager/discussions)
- Documentation: [Wiki](https://github.com/yourusername/crowdsec_manager/wiki)

---

**Built with ❤️ for the CrowdSec community**
