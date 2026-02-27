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

## Images

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

## Minimum Docker Compose

```yaml
services:
  crowdsec-manager:
    image: hhftechnology/crowdsec-manager:v1.0.0
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

For installation details, feature guides, and API reference, use the docs in [`docs`](https://crowdsec-manager.hhf.technology).

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

**Built with ❤️ for the CrowdSec/Pangolin community**
