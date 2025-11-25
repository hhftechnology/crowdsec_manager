# CrowdSec Manager - Usage Guide

> ⚠️ **BETA SOFTWARE** - Test thoroughly before production use

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
   sudo mkdir -p /root/config /root/config/traefik/logs
   mkdir -p ./backups ./data
   
   # Ensure network exists
   docker network create pangolin
   
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

### 2. Whitelist Your IP

Before configuring anything else, whitelist your current IP to avoid being blocked:

**Via Web UI:**
- Go to Whitelist page
- Click "Whitelist Current IP"
- Enable both CrowdSec and Traefik whitelisting

**Via API:**
```bash
# Get your public IP first
curl http://localhost:8080/api/ip/public

# Whitelist current IP comprehensively
curl -X POST http://localhost:8080/api/whitelist/current \
  -H "Content-Type: application/json" \
  -d '{
    "add_to_crowdsec": true,
    "add_to_traefik": true
  }'

# Verify whitelist
curl http://localhost:8080/api/whitelist/view | jq
```

### 3. Configure Backup Schedule

Set up automated backups:

**Via Web UI:**
- Navigate to Backup page
- Click "Schedule Backup"
- Configure cron expression (e.g., `0 2 * * *` for daily at 2 AM)
- Set retention period

**Via API:**
```bash
# Create a cron job for daily backups at 2 AM
curl -X POST http://localhost:8080/api/cron/setup \
  -H "Content-Type: application/json" \
  -d '{
    "schedule": "0 2 * * *",
    "command": "backup",
    "description": "Daily backup at 2 AM"
  }'

# List all cron jobs
curl http://localhost:8080/api/cron/list | jq
```

### 4. Configure Optional Services

You can enable or disable optional services (Pangolin, Gerbil) using environment variables in your `docker-compose.yml`.

**Configuration:**
```yaml
environment:
  - INCLUDE_PANGOLIN=true  # Set to false to disable Pangolin
  - INCLUDE_GERBIL=true    # Set to false to disable Gerbil
```

**Verify Service Status:**
```bash
# Check which services are active
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
- Filter by service (CrowdSec, Traefik, Pangolin, Gerbil)

### IP Management

**Check IP Status:**
```bash
# Check if IP is blocked
curl http://localhost:8080/api/ip/blocked/1.2.3.4

# Comprehensive security check
curl http://localhost:8080/api/ip/security/1.2.3.4 | jq
```

**Unban an IP:**
```bash
curl -X POST http://localhost:8080/api/ip/unban \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4"}'
```

**Whitelist an IP:**
```bash
# Whitelist single IP
curl -X POST http://localhost:8080/api/whitelist/manual \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "1.2.3.4",
    "add_to_crowdsec": true,
    "add_to_traefik": true
  }'

# Whitelist CIDR range
curl -X POST http://localhost:8080/api/whitelist/cidr \
  -H "Content-Type: application/json" \
  -d '{
    "cidr": "192.168.1.0/24",
    "add_to_crowdsec": true,
    "add_to_traefik": true
  }'
```

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

# Traefik logs
curl http://localhost:8080/api/logs/traefik

# Advanced Traefik analysis
curl http://localhost:8080/api/logs/traefik/advanced | jq

# Specific service logs
curl http://localhost:8080/api/logs/pangolin
```

**Stream Logs (WebSocket):**
- Use the Logs page in web UI
- Select service and click "Stream Logs"
- Real-time log viewing

## Advanced Usage

### Backup Management

**Create Manual Backup:**
```bash
# Create backup
curl -X POST http://localhost:8080/api/backup/create \
  -H "Content-Type: application/json" \
  -d '{"dry_run": false}'

# Dry run first (recommended)
curl -X POST http://localhost:8080/api/backup/create \
  -H "Content-Type: application/json" \
  -d '{"dry_run": true}'
```

**List Backups:**
```bash
# List all backups
curl http://localhost:8080/api/backup/list | jq

# Get latest backup
curl http://localhost:8080/api/backup/latest | jq
```

**Restore from Backup:**
```bash
# List backups first to get backup ID
curl http://localhost:8080/api/backup/list | jq

# Restore specific backup
curl -X POST http://localhost:8080/api/backup/restore \
  -H "Content-Type: application/json" \
  -d '{
    "backup_id": "backup-20240101-120000",
    "confirm": true
  }'
```

**Cleanup Old Backups:**
```bash
# Manual cleanup (respects RETENTION_DAYS)
curl -X POST http://localhost:8080/api/backup/cleanup

# Delete specific backup
curl -X DELETE http://localhost:8080/api/backup/backup-20240101-120000
```

### Service Updates

**Check Current Versions:**
```bash
curl http://localhost:8080/api/update/current-tags | jq
```

**Update Services:**
```bash
# Update with CrowdSec
curl -X POST http://localhost:8080/api/update/with-crowdsec \
  -H "Content-Type: application/json" \
  -d '{
    "tag": "latest",
    "dry_run": false
  }'

# Update without CrowdSec
curl -X POST http://localhost:8080/api/update/without-crowdsec \
  -H "Content-Type: application/json" \
  -d '{
    "tag": "latest",
    "dry_run": false
  }'
```

**⚠️ Always do a dry run first:**
```bash
curl -X POST http://localhost:8080/api/update/with-crowdsec \
  -H "Content-Type: application/json" \
  -d '{"tag": "latest", "dry_run": true}'
```

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

### Captcha Configuration

**Setup Cloudflare Turnstile:**
```bash
curl -X POST http://localhost:8080/api/captcha/setup \
  -H "Content-Type: application/json" \
  -d '{
    "site_key": "your-site-key",
    "secret_key": "your-secret-key",
    "enabled": true
  }'
```

**Check Captcha Status:**
```bash
curl http://localhost:8080/api/captcha/status | jq
```

### Traefik Integration

**Check Integration Status:**
```bash
curl http://localhost:8080/api/traefik/integration | jq
```

**View Configuration:**
```bash
curl http://localhost:8080/api/traefik/config | jq
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

1. **Always Whitelist Your IP First**
   - Before making any changes
   - Use comprehensive whitelisting (CrowdSec + Traefik)

2. **Regular Backups**
   - Set up automated daily backups
   - Test restoration periodically
   - Keep backups off-server

3. **Monitor Decisions**
   - Review blocked IPs regularly
   - Investigate false positives
   - Adjust scenarios as needed

4. **Update Carefully**
   - Always do dry runs first
   - Test updates in staging
   - Have rollback plan ready

### Operations

1. **Health Monitoring**
   - Check system health daily
   - Set up alerts for failures
   - Monitor resource usage

2. **Log Management**
   - Review logs regularly
   - Use advanced analysis features
   - Archive old logs

3. **Backup Strategy**
   - Daily automated backups
   - Weekly manual verification
   - Monthly restoration tests

4. **Update Strategy**
   - Test updates in staging first
   - Schedule maintenance windows
   - Keep change logs

### Performance

1. **Resource Monitoring**
   - Monitor CPU and memory
   - Check disk space for backups
   - Review log file sizes

2. **Optimization**
   - Clean old backups regularly
   - Archive old logs
   - Review and optimize scenarios

## Common Workflows

### Workflow 1: Initial Server Setup

```bash
# 1. Deploy container
docker compose up -d

# 2. Verify health
curl http://localhost:8080/api/health/complete

# 3. Whitelist your IP
curl -X POST http://localhost:8080/api/whitelist/current \
  -H "Content-Type: application/json" \
  -d '{"add_to_crowdsec": true, "add_to_traefik": true}'

# 4. Create initial backup
curl -X POST http://localhost:8080/api/backup/create \
  -H "Content-Type: application/json" \
  -d '{"dry_run": false}'

# 5. Setup automated backups
curl -X POST http://localhost:8080/api/cron/setup \
  -H "Content-Type: application/json" \
  -d '{
    "schedule": "0 2 * * *",
    "command": "backup",
    "description": "Daily backup"
  }'
```

### Workflow 2: Unbanning a False Positive

```bash
# 1. Check IP status
curl http://localhost:8080/api/ip/security/1.2.3.4 | jq

# 2. Unban the IP
curl -X POST http://localhost:8080/api/ip/unban \
  -H "Content-Type: application/json" \
  -d '{"ip": "1.2.3.4"}'

# 3. Whitelist to prevent future blocks
curl -X POST http://localhost:8080/api/whitelist/manual \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "1.2.3.4",
    "add_to_crowdsec": true,
    "add_to_traefik": true
  }'

# 4. Verify
curl http://localhost:8080/api/ip/security/1.2.3.4 | jq
```

### Workflow 3: Updating Services

```bash
# 1. Check current versions
curl http://localhost:8080/api/update/current-tags | jq

# 2. Create backup before update
curl -X POST http://localhost:8080/api/backup/create \
  -H "Content-Type: application/json" \
  -d '{"dry_run": false}'

# 3. Dry run update
curl -X POST http://localhost:8080/api/update/with-crowdsec \
  -H "Content-Type: application/json" \
  -d '{"tag": "latest", "dry_run": true}'

# 4. Perform actual update
curl -X POST http://localhost:8080/api/update/with-crowdsec \
  -H "Content-Type: application/json" \
  -d '{"tag": "latest", "dry_run": false}'

# 5. Verify health after update
curl http://localhost:8080/api/health/complete | jq
```

### Workflow 4: Analyzing Attack Patterns

```bash
# 1. View recent decisions
curl http://localhost:8080/api/crowdsec/decisions | jq

# 2. Analyze Traefik logs
curl http://localhost:8080/api/logs/traefik/advanced | jq

# 3. Check specific IP
curl http://localhost:8080/api/ip/security/1.2.3.4 | jq

# 4. Review metrics
curl http://localhost:8080/api/crowdsec/metrics | jq
```

### Workflow 5: Disaster Recovery

```bash
# 1. List available backups
curl http://localhost:8080/api/backup/list | jq

# 2. Verify backup integrity
curl http://localhost:8080/api/backup/latest | jq

# 3. Restore from backup
curl -X POST http://localhost:8080/api/backup/restore \
  -H "Content-Type: application/json" \
  -d '{
    "backup_id": "backup-20240101-120000",
    "confirm": true
  }'

# 4. Verify restoration
curl http://localhost:8080/api/health/complete | jq
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

### Issue: Backup Failures

**Symptoms:** Backup creation fails or incomplete

**Solutions:**
```bash
# Check backup directory permissions
ls -la ./backups
chmod 755 ./backups

# Check disk space
df -h

# Verify volume mount
docker inspect crowdsec-manager | grep -A 5 Mounts

# Check logs
docker logs crowdsec-manager | grep -i backup
```

### Issue: Network Connectivity Problems

**Symptoms:** Cannot reach other containers or services

**Solutions:**
```bash
# Verify network exists
docker network ls | grep pangolin

# Check container network
docker inspect crowdsec-manager | grep -A 10 Networks

# Recreate network if needed
docker network rm pangolin
docker network create pangolin
docker compose up -d
```

### Issue: Logs Not Appearing

**Symptoms:** Log pages show empty or errors

**Solutions:**
```bash
# Verify log file paths
ls -la /root/config/traefik/logs/

# Check log file permissions
sudo chmod 644 /root/config/traefik/logs/*.log

# Verify volume mounts
docker inspect crowdsec-manager | grep -A 5 Mounts

# Test log access
docker exec crowdsec-manager ls -la /var/log/traefik
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

# Reset database (⚠️ data loss)
rm ./data/settings.db
docker compose restart crowdsec-manager
```

## Additional Resources

- **Main README**: See [README.md](README.md) for installation and configuration
- **API Documentation**: Complete API reference in README
- **GitHub Issues**: Report bugs and request features
- **CrowdSec Docs**: [https://docs.crowdsec.net](https://docs.crowdsec.net)

---

**⚠️ Remember: This is BETA software. Always test thoroughly before production use!**

