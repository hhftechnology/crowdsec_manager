# PANGOLIN-CROWDSEC-MANAGER

## Overview

This project provides a comprehensive management tool for CrowdSec integration with Pangolin, offering a complete CLI interface to manage and monitor security settings. The CrowdSec Manager helps administrators handle IP blocking, whitelisting, captcha protection, and various security configurations through an interactive command-line interface.

## Architecture

The solution consists of the following core components:

- **CrowdSec**: Security engine that detects and blocks malicious activity
- **Traefik**: Reverse proxy with CrowdSec integration for enforcing security decisions
- **Pangolin**: Main application being protected
- **Gerbil**: Supporting service

## Key Features

- **Health & Diagnostics**
  - System health monitoring
  - Comprehensive diagnostic checks
  - CrowdSec bouncers and metrics verification
  - Traefik integration validation

- **IP Management**
  - Block/unblock IPs
  - IP whitelisting (including current public IP)
  - Security status checking for specific IPs
  - List current CrowdSec decisions (blocks/captchas)

- **Security Configuration**
  - CrowdSec Console enrollment for community protection
  - Custom security scenarios for specific threats
  - Captcha protection with Cloudflare Turnstile

- **Logging & Monitoring**
  - View and follow CrowdSec and Traefik logs
  - Traffic analysis tools

## Security Scenarios

Includes pre-configured security scenarios for protecting Pangolin:

- Authentication bruteforce detection
- API abuse protection
- Resource scanning prevention
- HTTP flood protection

## Requirements

- Docker and Docker Compose
- Containers: crowdsec, traefik, pangolin, gerbil
- Configuration directory structure with traefik configs

## Usage

Run the master script to access the interactive menu:

```bash
./master.sh
```

Follow the on-screen menu to:
1. Check system health
2. Manage IP whitelists/blocks
3. Configure security settings
4. Set up Cloudflare Turnstile captcha
5. Monitor logs and activities

## Security Whitelist Management

The system supports whitelisting for:
- Current public IP address
- Manual IP entry
- Standard private networks (10.0.0.0/8, 192.168.0.0/16, etc.)
- Custom IP ranges

## Captcha Protection

The tool can configure Cloudflare Turnstile captcha for suspicious connections:
- Integrates with CrowdSec remediation profiles
- Custom HTML templates for captcha pages
- Grace period configuration

## Folder Structure

```
./config/
  ├── crowdsec/
  │   └── profiles.yaml
  ├── traefik/
  │   ├── dynamic_config.yml
  │   └── conf/
  │       └── captcha.html
```

## Troubleshooting

The manager includes various diagnostic tools for troubleshooting:
- Container health checks
- CrowdSec decisions verification
- Log analysis for Traefik and CrowdSec
- Middleware configuration validation

## Security Best Practices

- Uses secure whitelisting for trusted IPs
- Implements multiple defense layers (IP blocks, captcha, rate limiting)
- Custom scenarios for application-specific threats
- Integration with community threat intelligence via CrowdSec Console