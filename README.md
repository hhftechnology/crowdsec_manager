<div align="center">
  <h1><a href="https://github.com/hhftechnology/crowdsec_manager">CrowdSec Manager</a></h1>

[![Docker](https://img.shields.io/docker/pulls/hhftechnology/crowdsec-manager?style=flat-square)](https://hub.docker.com/r/hhftechnology/crowdsec-manager)
![Stars](https://img.shields.io/github/stars/hhftechnology/crowdsec_manager?style=flat-square)
[![Discord](https://img.shields.io/discord/994247717368909884?logo=discord&style=flat-square)](https://discord.gg/HDCt9MjyMJ)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8.svg)
![React Version](https://img.shields.io/badge/react-18.3-61DAFB.svg)
![Status](https://img.shields.io/badge/status-stable-22c55e.svg)
</div>

CrowdSec Manager is a web-based management interface for CrowdSec operations, Traefik integration, decisions, scenarios, backups, and logs.

## Stable release

- Current baseline: `1.0.0`
- Multi-proxy support: not available in this release

## Minimum Docker Compose

```yaml
services:
  crowdsec-manager:
    image: hhftechnology/crowdsec-manager:1.0.0
    container_name: crowdsec-manager
    restart: unless-stopped
    expose:
      - "8080"
    environment:
      # Core Configuration
      - PORT=8080
      - ENVIRONMENT=production
      - TRAEFIK_DYNAMIC_CONFIG=/etc/traefik/dynamic_config.yml
      - TRAEFIK_CONTAINER_NAME=traefik
      - TRAEFIK_STATIC_CONFIG=/etc/traefik/traefik_config.yml
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /root/config:/app/config
      - /root/docker-compose.yml:/app/docker-compose.yml
      - ./backups:/app/backups
      - ./data:/app/data
    networks:
      - pangolin

networks:
  pangolin:
    external: true
```

## Run

```bash
mkdir -p ./backups ./data
docker network create pangolin
docker compose up -d
```

## Verify

```bash
curl http://localhost:8080/health
```

## Documentation

For installation details, feature guides, and API reference, use the docs in [`docs/`](/docs).
