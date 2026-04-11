# CrowdSec Manager - Usage Guide

> **BETA SOFTWARE** - Test thoroughly before production use

This guide provides detailed usage instructions, examples, and best practices for CrowdSec Manager.

## Table of Contents

- [Quick Start](#quick-start)
- [Initial Configuration](#initial-configuration)
- [Daily Operations](#daily-operations)
- [Advanced Usage](#advanced-usage)
- [Best Practices](#best-practices)
- [Common Workflows](#common-workflows)
- [Troubleshooting](#troubleshooting)

## Quick Start

### First-Time Setup

1. **Deploy to Test Environment**
   ```bash
   # Create required directories
   mkdir -p ./data ./logs/app ./config

   # Start the container
   docker compose up -d
   ```

2. **Verify Installation**
   ```bash
   # Check container status
   docker ps | grep crowdsec-manager

   # Check health
   curl http://localhost:8080/health

   # View logs
   docker logs -f crowdsec-manager
   ```

3. **Access Web Interface**
   - Open browser to `http://your-server-ip:8080`
   - Verify all services are running

## Initial Configuration

### 1. System Health Check

First, verify your entire stack is healthy:

**Via Web UI:**
- Navigate to Dashboard
- Check all service statuses
- Review any warnings or errors

**Via API:**
```bash
# Complete system diagnostics
curl http://localhost:8080/api/health/complete | jq

# Stack status only
curl http://localhost:8080/api/health/stack | jq
```

## Daily Operations

### Monitoring System Health

**Check Service Status:**
```bash
# Quick health check
curl http://localhost:8080/api/health/stack

# Detailed diagnostics
curl http://localhost:8080/api/health/complete
```

**Monitor Logs:**
- Use the Logs page in the web UI
- Stream logs in real-time
- Filter by service (CrowdSec)

### Viewing Decisions

**Check CrowdSec Decisions:**
```bash
# List all decisions
curl http://localhost:8080/api/crowdsec/decisions | jq

# View in web UI
# Navigate to Decision Analysis page
```

**View Bouncers:**
```bash
curl http://localhost:8080/api/crowdsec/bouncers | jq
```

### Log Analysis

**View Service Logs:**
```bash
# CrowdSec logs
curl http://localhost:8080/api/logs/crowdsec
```

**Stream Logs (WebSocket):**
- Use the Logs page in web UI
- Select service and click "Stream Logs"
- Real-time log viewing

## Advanced Usage

### Custom Scenarios

**Install Custom Scenario:**
```bash
curl -X POST http://localhost:8080/api/scenarios/setup \
  -H "Content-Type: application/json" \
  -d '{
    "scenario_name": "custom-scenario",
    "scenario_content": "---\nname: custom-scenario\n..."
  }'
```

**List Installed Scenarios:**
```bash
curl http://localhost:8080/api/scenarios/list | jq
```

### CrowdSec Console Enrollment

**Enroll with Console (Two-Step Process):**

1. **Submit Enrollment Key:**
   ```bash
   curl -X POST http://localhost:8080/api/crowdsec/enroll \
     -H "Content-Type: application/json" \
     -d '{
       "enrollment_key": "your-console-key"
     }'
   ```

2. **Check Enrollment Status:**
   The enrollment process may take a few moments to validate. Poll the status endpoint:
   ```bash
   curl http://localhost:8080/api/crowdsec/status | jq
   ```

   Expected output when successful:
   ```json
   {
     "success": true,
     "data": {
       "enrolled": true,
       "validated": true
     }
   }
   ```

## Best Practices

### Security

1. **Monitor Decisions**
   - Review blocked IPs regularly
   - Investigate false positives
   - Adjust scenarios as needed

### Operations

1. **Health Monitoring**
   - Check system health daily
   - Set up alerts for failures
   - Monitor resource usage

2. **Log Management**
   - Review logs regularly
   - Use advanced analysis features
   - Archive old logs

## Common Workflows

### Workflow 1: Initial Server Setup

```bash
# 1. Deploy container
docker compose up -d

# 2. Verify health
curl http://localhost:8080/api/health/complete
```

### Workflow 2: Analyzing Attack Patterns

```bash
# 1. View recent decisions
curl http://localhost:8080/api/crowdsec/decisions | jq

# 2. Check CrowdSec metrics
curl http://localhost:8080/api/crowdsec/metrics | jq
```

## Troubleshooting

### Issue: Cannot Access Web Interface

**Symptoms:** Browser shows connection refused or timeout

**Solutions:**
```bash
# Check if container is running
docker ps | grep crowdsec-manager

# Check container logs
docker logs crowdsec-manager

# Verify port exposure
docker port crowdsec-manager

# Check firewall
sudo ufw status
sudo ufw allow 8080/tcp
```

### Issue: Docker Socket Permission Denied

**Symptoms:** Container logs show Docker connection errors

**Solutions:**
```bash
# Check socket permissions
ls -la /var/run/docker.sock

# Fix permissions (temporary)
sudo chmod 666 /var/run/docker.sock

# Fix permissions (permanent - add user to docker group)
sudo usermod -aG docker $USER
newgrp docker
```

### Issue: Network Connectivity Problems

**Symptoms:** Cannot reach other containers or services

**Solutions:**
```bash
# Verify network exists
docker network ls | grep crowdsec-network

# Check container network
docker inspect crowdsec-manager | grep -A 10 Networks

# Recreate network if needed
docker compose down
docker compose up -d
```

### Issue: Database Errors

**Symptoms:** Settings not saving or database errors

**Solutions:**
```bash
# Check database file
ls -la ./data/settings.db

# Verify permissions
chmod 644 ./data/settings.db

# Check disk space
df -h

# Reset database (data loss)
rm ./data/settings.db
docker compose restart crowdsec-manager
```

## Additional Resources

- **Main README**: See [README.md](README.md) for installation and configuration
- **GitHub Issues**: Report bugs and request features
- **CrowdSec Docs**: [https://docs.crowdsec.net](https://docs.crowdsec.net)

---

**Remember: This is BETA software. Always test thoroughly before production use!**
