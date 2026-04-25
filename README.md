<div align="center">
  <h1><a href="https://github.com/hhftechnology/crowdsec_manager">CrowdSec Manager</a></h1>

[![Docker](https://img.shields.io/docker/pulls/hhftechnology/crowdsec-manager?style=flat-square)](https://hub.docker.com/r/hhftechnology/crowdsec-manager)
![Stars](https://img.shields.io/github/stars/hhftechnology/crowdsec_manager?style=flat-square)
[![Discord](https://img.shields.io/discord/994247717368909884?logo=discord&style=flat-square)](https://discord.gg/HDCt9MjyMJ)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-stable-22c55e.svg)
</div>

A web-based management interface for CrowdSec — decisions, alerts, allowlists, scenarios, hub, logs, backups, and Traefik integration.

## Mobile App

<div align="center">
<a href="https://apps.apple.com/us/app/#"><img width="135" height="39" alt="Download on the App Store" src="https://github.com/user-attachments/assets/45e31a11-cf6b-40a2-a083-6dc8d1f01291" /></a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="https://play.google.com/store/apps/details?id=com.crowdsec.manager.mobile"><img width="135" height="39" alt="Get it on Google Play" src="https://github.com/user-attachments/assets/acbba639-858f-4c74-85c7-92a4096efbf5" /></a>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="https://play.google.com/store/apps/details?id=com.crowdsec.manager.independent"><img width="135" height="39" alt="Get it on Google Play (Independent)" src="https://github.com/user-attachments/assets/acbba639-858f-4c74-85c7-92a4096efbf5" /></a>
</div>

## Mobile Screenshots

<table>
  <tr>
    <td align="center">
      <img src="images/mobile/3.png" width="180" alt="Connection setup (3.png)"><br>
      <sub>Connection Setup</sub>
    </td>
    <td align="center">
      <img src="images/mobile/1.png" width="180" alt="Dashboard overview (1.png)"><br>
      <sub>Dashboard Overview</sub>
    </td>
    <td align="center">
      <img src="images/mobile/2.png" width="180" alt="Security IP check (2.png)"><br>
      <sub>Security IP Check</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="images/mobile/4.png" width="180" alt="Security alerts list (4.png)"><br>
      <sub>Security Alerts List</sub>
    </td>
    <td align="center">
      <img src="images/mobile/5.png" width="180" alt="Security metrics (5.png)"><br>
      <sub>Security Metrics</sub>
    </td>
    <td align="center">
      <img src="images/mobile/6.png" width="180" alt="Logs viewer (6.png)"><br>
      <sub>Logs Viewer</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="images/mobile/7.png" width="180" alt="Management home (7.png)"><br>
      <sub>Management Home</sub>
    </td>
    <td align="center">
      <img src="images/mobile/8.png" width="180" alt="Allowlists management (8.png)"><br>
      <sub>Allowlists Management</sub>
    </td>
    <td align="center">
      <img src="images/mobile/9.png" width="180" alt="Hub management (9.png)"><br>
      <sub>Hub Management</sub>
    </td>
  </tr>
  <tr>
    <td align="center">
      <img src="images/mobile/10.png" width="180" alt="Scenarios management (10.png)"><br>
      <sub>Scenarios Management</sub>
    </td>
    <td align="center">
      <img src="images/mobile/11.png" width="180" alt="Container controls (11.png)"><br>
      <sub>Container Controls</sub>
    </td>
    <td align="center">
      <img src="images/mobile/12.png" width="180" alt="Terminal shell (12.png)"><br>
      <sub>Terminal Shell</sub>
    </td>
  </tr>
</table>

Native iOS and Android app. Supports **Pangolin** (token-based remote access) and **Basis** (direct URL) connection modes.

## Release

- Version: `2.3.4`
- Pangolin image: `hhftechnology/crowdsec-manager:latest` — full stack with Traefik, Pangolin, Gerbil
- Independent image: `hhftechnology/crowdsec-manager:independent` — CrowdSec only, no Traefik
- Image size (linux/amd64): <!-- IMAGE_SIZE_START -->44MB<!-- IMAGE_SIZE_END -->

## Quick Start

### Pangolin (full stack)

```bash
git clone https://github.com/hhftechnology/crowdsec_manager.git
cd crowdsec_manager
mkdir -p ./config/crowdsec ./config/traefik ./backups ./logs/app ./logs/traefik ./data
docker compose up -d
```

### Independent (CrowdSec only)

```bash
mkdir -p ./config/crowdsec ./logs/app ./data
```

```yaml
services:
  crowdsec-manager:
    image: hhftechnology/crowdsec-manager:independent
    container_name: crowdsec-manager
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - ENVIRONMENT=production
      - CONFIG_DIR=/app/config
      - DATABASE_PATH=/app/data/settings.db
      - INCLUDE_CROWDSEC=true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./config:/app/config
      - ./logs/app:/app/logs
      - ./data:/app/data
    networks:
      - crowdsec-network
    depends_on:
      - crowdsec

  crowdsec:
    image: crowdsecurity/crowdsec:latest
    container_name: crowdsec
    environment:
      - COLLECTIONS=crowdsecurity/linux
    volumes:
      - ./config/crowdsec/acquis.yaml:/etc/crowdsec/acquis.yaml:ro
      - crowdsec-db:/var/lib/crowdsec/data/
      - crowdsec-config:/etc/crowdsec/
    networks:
      - crowdsec-network

networks:
  crowdsec-network:
    driver: bridge

volumes:
  crowdsec-db:
  crowdsec-config:
```

```bash
docker compose up -d
curl http://localhost:8080/api/health/stack
```

## Screenshots

<img width="1200" height="630" alt="Dashboard" src="/images/dashboard-overview-countries-systems.jpeg"/>
<img width="1200" height="630" alt="Health & Diagnostics" src="/images/health-diagnostics-overview.jpeg"/>
<img width="1200" height="630" alt="Decisions Analysis" src="/images/decisions-analysis-overview.jpeg"/>
<img width="1200" height="630" alt="Alert Analysis" src="/images/alerts-analysis-overview.jpeg"/>
<img width="1200" height="630" alt="Allowlists" src="/images/allowlists-management.jpeg"/>
<img width="1200" height="630" alt="Hub" src="/images/hub-home-categories.jpeg"/>
<img width="1200" height="630" alt="Logs" src="/images/logs-service-logs.jpeg"/>
<img width="1200" height="630" alt="Terminal" src="/images/terminal-container-shell.png"/>



## Documentation

Full installation guide, configuration reference, mobile app setup, and API docs:
[crowdsec-manager.hhf.technology](https://crowdsec-manager.hhf.technology)

## License

MIT — see [LICENSE](LICENSE).

## Support

- [GitHub Issues](https://github.com/hhftechnology/crowdsec_manager/issues)
- [Discord](https://discord.gg/HDCt9MjyMJ)
