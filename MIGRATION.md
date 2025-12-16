# Migration Guide

This guide helps existing CrowdSec Manager users migrate to the new multi-proxy architecture. The system maintains 100% backward compatibility, so existing Traefik installations continue working without any configuration changes.

## Overview

CrowdSec Manager has been enhanced to support multiple reverse proxy types while maintaining complete backward compatibility with existing Traefik deployments. Key improvements include:

- **Multi-Proxy Support**: Traefik, Nginx Proxy Manager, Caddy, HAProxy, Zoraxy, and Standalone modes
- **Adaptive UI**: Interface automatically adapts to show features available for your proxy type
- **Backward Compatibility**: All existing configurations, API endpoints, and environment variables continue working
- **Automatic Migration**: Database and configuration migration happens automatically on first startup

## Migration Scenarios

### Scenario 1: Existing Traefik Users (Zero Changes Required)

**Status**: ✅ **No action required** - Your installation will work exactly as before.

If you have an existing CrowdSec Manager installation with Traefik:

1. **Update the Docker image** to the latest version
2. **Restart the container** - that's it!

The system will:
- Automatically detect your Traefik configuration
- Migrate your database schema (preserving all data)
- Map legacy environment variables to new proxy settings
- Continue providing all existing functionality

**What you'll see**:
- Same interface and functionality as before
- New "Traefik Mode" indicator in the UI
- All existing features continue working
- Optional: Access to new generic terminology alongside legacy terms

### Scenario 2: Want to Switch to a Different Proxy

**Status**: ⚠️ **Requires new deployment** - Proxy type cannot be changed after initial setup.

If you want to switch from Traefik to another proxy type:

1. **Backup your current configuration**:
   ```bash
   # Create backup through the UI or API
   curl -X POST http://localhost:8080/api/backup/create
   ```

2. **Deploy a new instance** with your desired proxy type:
   ```bash
   # Set new proxy type
   export PROXY_TYPE=nginx  # or caddy, haproxy, etc.
   
   # Deploy new instance
   docker-compose --profile nginx up -d
   ```

3. **Migrate your CrowdSec configuration** manually (scenarios, allowlists, etc.)

**Note**: Direct proxy type switching is not supported to maintain deployment consistency and prevent configuration conflicts.

### Scenario 3: New Multi-Proxy Deployment

**Status**: ✅ **Follow the Quick Start guide** in the main README.

For new deployments, simply choose your proxy type during initial setup.

## Automatic Migration Details

### Database Migration

The system automatically performs the following database migrations on first startup:

1. **Schema Updates**:
   ```sql
   -- Adds new proxy-related columns
   ALTER TABLE settings ADD COLUMN proxy_type TEXT NOT NULL DEFAULT 'traefik';
   ALTER TABLE settings ADD COLUMN proxy_enabled INTEGER NOT NULL DEFAULT 1;
   ALTER TABLE settings ADD COLUMN compose_mode TEXT NOT NULL DEFAULT 'single';
   
   -- Creates new proxy_settings table
   CREATE TABLE proxy_settings (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       proxy_type TEXT NOT NULL DEFAULT 'traefik',
       container_name TEXT NOT NULL,
       config_paths TEXT NOT NULL DEFAULT '{}',
       custom_settings TEXT NOT NULL DEFAULT '{}',
       enabled_features TEXT NOT NULL DEFAULT '[]',
       created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
       updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
   );
   ```

2. **Data Migration**:
   - Existing Traefik configurations are automatically detected and preserved
   - Legacy environment variables are mapped to new proxy settings
   - All existing whitelist, backup, and configuration data is preserved

### Environment Variable Mapping

Legacy environment variables are automatically mapped to new proxy settings:

| Legacy Variable           | New Variable              | Notes                    |
| ------------------------- | ------------------------- | ------------------------ |
| `TRAEFIK_CONTAINER_NAME`  | `PROXY_CONTAINER_NAME`    | When `PROXY_TYPE=traefik` |
| `TRAEFIK_DYNAMIC_CONFIG`  | Stored in proxy_settings  | Preserved in database    |
| `TRAEFIK_STATIC_CONFIG`   | Stored in proxy_settings  | Preserved in database    |
| `TRAEFIK_ACCESS_LOG`      | Stored in proxy_settings  | Preserved in database    |
| `TRAEFIK_ERROR_LOG`       | Stored in proxy_settings  | Preserved in database    |

**Important**: Legacy variables continue to work indefinitely - no need to update your docker-compose.yml files.

### API Backward Compatibility

All existing API endpoints continue working with the same request/response formats:

#### Whitelist API Example

**Legacy request** (continues working):
```json
{
  "ip": "192.168.1.100",
  "add_to_crowdsec": true,
  "add_to_traefik": true
}
```

**New generic request** (also supported):
```json
{
  "ip": "192.168.1.100",
  "add_to_crowdsec": true,
  "add_to_proxy": true
}
```

**Response** (includes both formats):
```json
{
  "ip": "192.168.1.100",
  "in_crowdsec": true,
  "in_traefik": true,    // Legacy field (maintained forever)
  "in_proxy": true       // New generic field
}
```

## UI Changes for Existing Users

### What Stays the Same

- All existing functionality continues working
- Same navigation structure and page layouts
- All existing features (whitelist, captcha, logs, backups, etc.)
- Same API endpoints and response formats

### What's New

- **Proxy Type Indicator**: Shows "Traefik Mode" in the header
- **Generic Terminology**: Option to use generic terms like "Reverse Proxy Logs" instead of "Traefik Logs"
- **Feature Indicators**: Shows which features are available (all features for Traefik users)
- **Enhanced Health Monitoring**: More detailed proxy-specific health information

### UI Terminology

The interface now supports both legacy and generic terminology:

| Legacy Term        | Generic Term           | Notes                           |
| ------------------ | ---------------------- | ------------------------------- |
| "Traefik Logs"     | "Reverse Proxy Logs"   | Both terms shown in UI         |
| "Traefik Whitelist"| "Proxy Whitelist"      | Both options available         |
| "Traefik Health"   | "Proxy Health"         | Enhanced with more details     |

## Rollback Instructions

If you need to rollback to the previous version:

1. **Stop the new version**:
   ```bash
   docker-compose down
   ```

2. **Restore your backup** (if you created one):
   ```bash
   # Restore database backup
   cp backups/settings_backup.db data/settings.db
   ```

3. **Use the previous Docker image**:
   ```bash
   # In your docker-compose.yml, change:
   image: hhftechnology/crowdsec-manager:previous-version
   
   # Then restart
   docker-compose up -d
   ```

**Note**: The database migration is backward compatible, so rollback should work seamlessly.

## Verification Steps

After migration, verify everything is working correctly:

### 1. Check System Health

```bash
# Verify all containers are running
docker-compose ps

# Check system health
curl http://localhost:8080/api/health/stack

# Check proxy information
curl http://localhost:8080/api/proxy/current
```

Expected response for Traefik users:
```json
{
  "type": "traefik",
  "enabled": true,
  "container_name": "traefik",
  "running": true,
  "supported_features": ["whitelist", "captcha", "logs", "bouncer", "health"],
  "config_files": ["/etc/traefik/dynamic_config.yml", "/etc/traefik/traefik_config.yml"]
}
```

### 2. Test Existing Functionality

```bash
# Test whitelist functionality (legacy API)
curl -X POST http://localhost:8080/api/whitelist/current \
  -H "Content-Type: application/json" \
  -d '{"add_to_crowdsec": true, "add_to_traefik": true}'

# Test new generic API
curl -X POST http://localhost:8080/api/whitelist/current \
  -H "Content-Type: application/json" \
  -d '{"add_to_crowdsec": true, "add_to_proxy": true}'

# Both should work identically
```

### 3. Verify UI Access

1. Open the web interface: `http://your-server-ip:8080`
2. Check that "Traefik Mode" is displayed in the header
3. Verify all menu items are available and functional
4. Test whitelist, logs, and backup functionality

### 4. Check Logs

```bash
# Check migration logs
docker logs crowdsec-manager | grep -i migration

# Should show successful migration messages
```

## Troubleshooting

### Migration Issues

**Problem**: Container fails to start after update
**Solution**: 
```bash
# Check logs for specific error
docker logs crowdsec-manager

# Common fix: ensure database file permissions
chmod 644 ./data/settings.db
```

**Problem**: Database migration fails
**Solution**:
```bash
# Backup current database
cp ./data/settings.db ./data/settings_backup.db

# Remove database to trigger fresh migration
rm ./data/settings.db

# Restart container
docker-compose restart crowdsec-manager
```

**Problem**: Legacy environment variables not recognized
**Solution**: Legacy variables are still supported. Check your docker-compose.yml for typos:
```yaml
environment:
  - TRAEFIK_CONTAINER_NAME=traefik  # Still works
  - PROXY_TYPE=traefik              # Auto-detected if not set
```

### API Compatibility Issues

**Problem**: API responses missing legacy fields
**Solution**: This shouldn't happen. If it does, please report it as a bug. The system should always include both legacy and new fields.

**Problem**: Whitelist operations not working
**Solution**: 
```bash
# Check proxy status
curl http://localhost:8080/api/proxy/current

# Verify Traefik container is running
docker ps | grep traefik

# Check Traefik configuration files exist
ls -la ./config/traefik/
```

### UI Issues

**Problem**: Interface shows "Standalone Mode" instead of "Traefik Mode"
**Solution**: 
```bash
# Check proxy detection
curl http://localhost:8080/api/proxy/current

# If proxy_type is not 'traefik', check environment variables
docker exec crowdsec-manager env | grep PROXY
```

**Problem**: Some features missing from UI
**Solution**: For Traefik users, all features should be available. Check:
```bash
# Verify supported features
curl http://localhost:8080/api/proxy/features

# Should return: ["whitelist", "captcha", "logs", "bouncer", "health"]
```

## Support

If you encounter issues during migration:

1. **Check the logs**: `docker logs crowdsec-manager`
2. **Verify your configuration**: Ensure all required files and directories exist
3. **Test API endpoints**: Use curl to verify functionality
4. **Create an issue**: [GitHub Issues](https://github.com/hhftechnology/crowdsec_manager/issues) with:
   - Your previous version
   - Current version
   - Error logs
   - Configuration details (sanitized)

## Summary

The migration to multi-proxy CrowdSec Manager is designed to be seamless for existing Traefik users:

- ✅ **Zero configuration changes required**
- ✅ **All existing functionality preserved**
- ✅ **Automatic database migration**
- ✅ **API backward compatibility maintained**
- ✅ **UI enhancements without breaking changes**

Your existing installation will continue working exactly as before, with the added benefit of enhanced monitoring, improved UI, and the foundation for future multi-proxy capabilities.