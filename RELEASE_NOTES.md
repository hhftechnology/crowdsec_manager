# CrowdSec Manager v2.0.0 - Multi-Proxy Architecture Release

## 🚀 Major Release: Multi-Proxy Support

CrowdSec Manager v2.0.0 introduces comprehensive support for multiple reverse proxy types while maintaining 100% backward compatibility with existing Traefik deployments.

## ✨ New Features

### Multi-Proxy Architecture
- **6 Proxy Types Supported**: Traefik, Nginx Proxy Manager, Caddy, HAProxy, Zoraxy, and Standalone mode
- **Plugin Architecture**: Extensible adapter system for adding new proxy types
- **Feature Detection**: Automatic detection of supported features per proxy type
- **Graceful Degradation**: Unsupported features are handled transparently

### Enhanced User Interface
- **Adaptive UI**: Interface adapts based on selected proxy capabilities
- **Generic Terminology**: Proxy-agnostic language throughout the interface
- **Feature Indicators**: Clear indication of available vs unavailable features
- **Responsive Design**: Mobile-first design with tablet and desktop optimizations

### Flexible Deployment Options
- **Single File Mode**: Use Docker Compose profiles for all-in-one deployment
- **Separate File Mode**: Deploy core services and proxy services separately
- **Profile-Based Services**: Start only the services you need
- **Environment-Driven Configuration**: Configure everything via environment variables

### Traefik Add-ons (Pangolin & Gerbil)
- **Traefik-Specific**: Available only when Traefik is selected
- **Profile Integration**: Easy enable/disable via Docker Compose profiles
- **Backward Compatible**: Existing Pangolin/Gerbil setups continue working

## 🔄 Migration & Backward Compatibility

### Automatic Migration
- **Zero-Downtime**: Existing Traefik installations upgrade seamlessly
- **Configuration Preservation**: All settings are automatically migrated
- **Database Migration**: Automatic schema updates with rollback capability
- **Environment Variables**: Legacy variables are mapped to new proxy settings

### API Compatibility
- **Dual Field Support**: All API responses include both legacy and new field names
- **Endpoint Preservation**: All existing API endpoints continue working
- **Version Support**: No API deprecation - legacy support is permanent

### Migration Path
1. **Backup**: Automatic backup creation before migration
2. **Detection**: System detects existing Traefik configuration
3. **Migration**: Database and configuration files are updated
4. **Validation**: Post-migration validation ensures everything works
5. **Rollback**: Manual rollback procedures available if needed

## 📋 Proxy Feature Matrix

| Feature | Traefik | Nginx PM | Caddy | HAProxy | Zoraxy | Standalone |
|---------|---------|----------|-------|---------|--------|------------|
| **Whitelist Management** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Captcha Protection** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Log Parsing** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Bouncer Integration** | ✅ | ✅ | ✅ | ✅ | ⚠️ | ❌ |
| **Health Monitoring** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Add-ons (Pangolin/Gerbil)** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |

**Legend:**
- ✅ Fully supported
- ⚠️ Experimental support  
- ❌ Not supported

## 🛠 Technical Improvements

### Architecture
- **Plugin System**: Clean adapter pattern for proxy integrations
- **Feature Managers**: Modular feature implementation per proxy type
- **Factory Pattern**: Dynamic adapter loading and initialization
- **Interface Segregation**: Clean separation of concerns

### Performance
- **Lazy Loading**: Adapters initialized only when needed
- **Caching**: Feature detection and configuration caching
- **Batch Operations**: Efficient Docker container operations
- **Database Optimization**: Proper indexing and connection pooling

### Security
- **Input Validation**: Enhanced validation for all configuration inputs
- **Container Security**: Improved validation of container names and commands
- **Configuration Backup**: Automatic backup before destructive operations
- **Atomic Operations**: Configuration changes applied atomically

## 📦 Deployment Examples

### Quick Start - Traefik (Existing Users)
```bash
# No changes needed - automatic migration
docker-compose up -d
```

### New Deployment - Nginx Proxy Manager
```bash
# Copy configuration
cp examples/nginx/.env .env

# Deploy with Nginx PM
docker-compose --profile nginx up -d
```

### New Deployment - Caddy
```bash
# Copy configuration  
cp examples/caddy/.env .env

# Deploy with Caddy
docker-compose --profile caddy up -d
```

### Standalone Mode (CrowdSec Only)
```bash
# Copy configuration
cp examples/standalone/.env .env

# Deploy without proxy
docker-compose up -d
```

## 🔧 Configuration Changes

### New Environment Variables
```bash
# Multi-proxy configuration
PROXY_TYPE=traefik              # traefik|nginx|caddy|haproxy|zoraxy|standalone
PROXY_ENABLED=true              # Enable/disable proxy integration
PROXY_CONTAINER_NAME=traefik    # Proxy container name
COMPOSE_MODE=single             # single|separate deployment mode
```

### Legacy Variable Support
All existing Traefik variables continue to work:
```bash
TRAEFIK_CONTAINER_NAME=traefik  # Automatically mapped to PROXY_CONTAINER_NAME
TRAEFIK_DYNAMIC_CONFIG=...      # Preserved for Traefik adapter
TRAEFIK_STATIC_CONFIG=...       # Preserved for Traefik adapter
```

## 🧪 Testing & Quality

### Comprehensive Testing
- **Property-Based Testing**: 15 comprehensive correctness properties
- **Unit Testing**: 80%+ code coverage for all adapters
- **Integration Testing**: Docker Compose environments for each proxy type
- **Backward Compatibility**: Comprehensive legacy API testing

### Test Coverage
- **Backend**: Go testing with rapid for property-based tests
- **Frontend**: Jest with fast-check for property-based tests
- **API**: Complete endpoint testing with backward compatibility verification
- **Docker**: Automated testing of all deployment configurations

## 📚 Documentation Updates

### New Documentation
- **[REVERSE_PROXIES.md](REVERSE_PROXIES.md)**: Comprehensive proxy setup guides
- **[MIGRATION.md](MIGRATION.md)**: Detailed migration instructions
- **[examples/](examples/)**: Complete deployment examples for all proxy types

### Updated Documentation
- **[README.md](README.md)**: Updated with multi-proxy information
- **[DEPLOYMENT.md](DEPLOYMENT.md)**: Enhanced deployment strategies
- **[USAGE.md](USAGE.md)**: Updated usage instructions

## ⚠️ Breaking Changes

**None** - This release maintains 100% backward compatibility.

## 🐛 Bug Fixes

- Fixed container health check reliability
- Improved error handling for Docker operations
- Enhanced configuration validation
- Resolved race conditions in adapter initialization

## 🔮 Future Roadmap

### v2.1.0 (Planned)
- Additional proxy type support (Apache HTTP Server, Envoy)
- Enhanced monitoring and metrics
- Advanced security policies
- Multi-tenant support

### v2.2.0 (Planned)
- Kubernetes deployment support
- Cloud provider integrations
- Advanced analytics dashboard
- API rate limiting

## 📋 Upgrade Instructions

### For Existing Traefik Users
1. **Backup**: Create backup of current configuration
2. **Update**: Pull latest docker-compose.yml and Dockerfile
3. **Deploy**: Run `docker-compose up -d` (automatic migration)
4. **Verify**: Check that all services are running correctly

### For New Deployments
1. **Choose Proxy**: Select your preferred proxy type
2. **Copy Config**: Use appropriate example from `examples/` directory
3. **Customize**: Modify `.env` file for your environment
4. **Deploy**: Run deployment commands from example

### Rollback Procedure
If issues occur during migration:
1. **Stop Services**: `docker-compose down`
2. **Restore Backup**: Restore from automatic backup
3. **Use Legacy**: Deploy with previous version
4. **Report Issue**: Submit issue with migration logs

## 🤝 Contributing

We welcome contributions for:
- Additional proxy type adapters
- UI/UX improvements
- Documentation enhancements
- Bug fixes and optimizations

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📞 Support

- **Documentation**: Check updated docs and examples
- **Issues**: Report bugs via GitHub issues
- **Discussions**: Community support via GitHub discussions
- **Migration Help**: Detailed migration guide in [MIGRATION.md](MIGRATION.md)

---

**Full Changelog**: [v1.x.x...v2.0.0](https://github.com/crowdsec-manager/compare/v1.x.x...v2.0.0)

**Docker Images**: Available on Docker Hub with tags for each proxy type