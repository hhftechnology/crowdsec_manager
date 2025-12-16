# Version Compatibility Matrix

## CrowdSec Manager Compatibility

### Current Version: v2.0.0

| Component | Minimum Version | Recommended Version | Maximum Version | Notes |
|-----------|----------------|-------------------|-----------------|-------|
| **Docker** | 20.10.0 | 24.0.0+ | Latest | Required for all deployments |
| **Docker Compose** | 2.0.0 | 2.20.0+ | Latest | V2 syntax required |
| **Go** | 1.21 | 1.23+ | 1.23 | For building from source |
| **Node.js** | 18.0.0 | 20.0.0+ | Latest LTS | For frontend development |

## Reverse Proxy Compatibility

### Traefik
| Traefik Version | CrowdSec Manager | Bouncer Plugin | Features | Status |
|----------------|------------------|----------------|----------|--------|
| v3.0+ | v2.0.0+ | v1.3.0+ | Full Support | ✅ Recommended |
| v2.10+ | v2.0.0+ | v1.2.0+ | Full Support | ✅ Supported |
| v2.8-v2.9 | v2.0.0+ | v1.1.0+ | Limited | ⚠️ Basic Support |
| v2.0-v2.7 | Not Supported | - | - | ❌ Upgrade Required |

**Traefik Add-ons:**
- **Pangolin**: v1.0.0+ (Traefik v2.10+ required)
- **Gerbil**: v1.0.0+ (Traefik v2.10+ required)

### Nginx Proxy Manager
| NPM Version | CrowdSec Manager | Bouncer | Features | Status |
|-------------|------------------|---------|----------|--------|
| v2.11+ | v2.0.0+ | cs-nginx-bouncer v1.0.0+ | Log Parsing, Bouncer | ✅ Recommended |
| v2.10 | v2.0.0+ | cs-nginx-bouncer v1.0.0+ | Log Parsing, Bouncer | ✅ Supported |
| v2.9 | v2.0.0+ | cs-nginx-bouncer v0.9.0+ | Basic Support | ⚠️ Limited |
| v2.0-v2.8 | Not Supported | - | - | ❌ Upgrade Required |

### Caddy
| Caddy Version | CrowdSec Manager | Bouncer Module | Features | Status |
|---------------|------------------|----------------|----------|--------|
| v2.7+ | v2.0.0+ | caddy-crowdsec-bouncer v1.1.0+ | Bouncer, Health | ✅ Recommended |
| v2.6 | v2.0.0+ | caddy-crowdsec-bouncer v1.0.0+ | Bouncer, Health | ✅ Supported |
| v2.4-v2.5 | v2.0.0+ | caddy-crowdsec-bouncer v0.9.0+ | Basic Support | ⚠️ Limited |
| v2.0-v2.3 | Not Supported | - | - | ❌ Upgrade Required |

### HAProxy
| HAProxy Version | CrowdSec Manager | SPOA Bouncer | Features | Status |
|-----------------|------------------|--------------|----------|--------|
| v2.8+ | v2.0.0+ | cs-haproxy-bouncer v1.0.0+ | Bouncer, Health | ✅ Recommended |
| v2.6-v2.7 | v2.0.0+ | cs-haproxy-bouncer v1.0.0+ | Bouncer, Health | ✅ Supported |
| v2.4-v2.5 | v2.0.0+ | cs-haproxy-bouncer v0.9.0+ | Basic Support | ⚠️ Limited |
| v2.0-v2.3 | Not Supported | - | - | ❌ Upgrade Required |

### Zoraxy (Experimental)
| Zoraxy Version | CrowdSec Manager | Bouncer | Features | Status |
|----------------|------------------|---------|----------|--------|
| v3.0+ | v2.0.0+ | Experimental | Health Only | ⚠️ Experimental |
| v2.0+ | v2.0.0+ | Not Available | Health Only | ⚠️ Limited |
| v1.x | Not Supported | - | - | ❌ Not Supported |

## CrowdSec Compatibility

### CrowdSec Core
| CrowdSec Version | CrowdSec Manager | LAPI Version | Features | Status |
|------------------|------------------|--------------|----------|--------|
| v1.6+ | v2.0.0+ | v1.6+ | Full Support | ✅ Recommended |
| v1.5 | v2.0.0+ | v1.5 | Full Support | ✅ Supported |
| v1.4 | v2.0.0+ | v1.4 | Limited | ⚠️ Basic Support |
| v1.0-v1.3 | Not Supported | - | - | ❌ Upgrade Required |

### CrowdSec Collections
| Collection | Minimum Version | Recommended | Proxy Support |
|------------|----------------|-------------|---------------|
| **crowdsecurity/linux** | v0.2+ | Latest | All |
| **crowdsecurity/traefik** | v0.1+ | Latest | Traefik |
| **crowdsecurity/nginx** | v0.1+ | Latest | Nginx PM |
| **crowdsecurity/caddy** | v0.1+ | Latest | Caddy |
| **crowdsecurity/haproxy** | v0.1+ | Latest | HAProxy |

## Operating System Compatibility

### Container Host Requirements
| OS | Architecture | Docker Version | Status |
|----|-------------|----------------|--------|
| **Ubuntu 20.04+** | x86_64, arm64 | 20.10+ | ✅ Fully Supported |
| **Ubuntu 18.04** | x86_64 | 20.10+ | ✅ Supported |
| **Debian 11+** | x86_64, arm64 | 20.10+ | ✅ Fully Supported |
| **Debian 10** | x86_64 | 20.10+ | ✅ Supported |
| **CentOS 8+** | x86_64 | 20.10+ | ✅ Supported |
| **RHEL 8+** | x86_64 | 20.10+ | ✅ Supported |
| **Alpine Linux** | x86_64, arm64 | 20.10+ | ✅ Supported |
| **macOS** | x86_64, arm64 | Docker Desktop | ✅ Development Only |
| **Windows** | x86_64 | Docker Desktop | ⚠️ Development Only |

### Browser Compatibility (Web UI)
| Browser | Minimum Version | Recommended | Status |
|---------|----------------|-------------|--------|
| **Chrome** | 90+ | Latest | ✅ Fully Supported |
| **Firefox** | 88+ | Latest | ✅ Fully Supported |
| **Safari** | 14+ | Latest | ✅ Supported |
| **Edge** | 90+ | Latest | ✅ Supported |
| **Mobile Safari** | iOS 14+ | Latest | ✅ Mobile Optimized |
| **Chrome Mobile** | Android 10+ | Latest | ✅ Mobile Optimized |

## Migration Compatibility

### Upgrade Paths
| From Version | To Version | Migration Type | Downtime | Data Loss Risk |
|--------------|------------|----------------|----------|----------------|
| **v1.x** | **v2.0.0** | Automatic | None | None |
| **v0.x** | **v2.0.0** | Manual | Minimal | Low |
| **Legacy Traefik** | **v2.0.0** | Automatic | None | None |

### Rollback Support
| From Version | To Version | Rollback Type | Data Recovery |
|--------------|------------|---------------|---------------|
| **v2.0.0** | **v1.x** | Manual | Full |
| **v2.0.0** | **Legacy** | Manual | Partial |

## Environment Variable Compatibility

### Legacy Support (Permanent)
| Legacy Variable | New Variable | Status | Notes |
|----------------|--------------|--------|-------|
| `TRAEFIK_CONTAINER_NAME` | `PROXY_CONTAINER_NAME` | ✅ Supported | Auto-mapped when PROXY_TYPE=traefik |
| `TRAEFIK_DYNAMIC_CONFIG` | Proxy-specific | ✅ Supported | Preserved for Traefik adapter |
| `TRAEFIK_STATIC_CONFIG` | Proxy-specific | ✅ Supported | Preserved for Traefik adapter |
| `TRAEFIK_ACCESS_LOG` | Proxy-specific | ✅ Supported | Preserved for Traefik adapter |

### New Variables (v2.0.0+)
| Variable | Required | Default | Valid Values |
|----------|----------|---------|--------------|
| `PROXY_TYPE` | Yes | `traefik` | `traefik`, `nginx`, `caddy`, `haproxy`, `zoraxy`, `standalone` |
| `PROXY_ENABLED` | No | `true` | `true`, `false` |
| `COMPOSE_MODE` | No | `single` | `single`, `separate` |

## API Compatibility

### API Versions
| API Version | CrowdSec Manager | Status | Deprecation |
|-------------|------------------|--------|-------------|
| **v1** | v1.x, v2.0.0+ | ✅ Supported | Never |
| **v2** | v2.0.0+ | ✅ Current | N/A |

### Field Compatibility
| Field Type | v1 Fields | v2 Fields | Support |
|------------|-----------|-----------|---------|
| **Proxy Info** | `traefik_*` | `proxy_*` | Both Supported |
| **Whitelist** | `in_traefik` | `in_proxy` | Both Supported |
| **Health** | `traefik_status` | `proxy_status` | Both Supported |

## Performance Requirements

### Minimum System Requirements
| Component | CPU | Memory | Storage | Network |
|-----------|-----|--------|---------|---------|
| **CrowdSec Manager** | 1 vCPU | 512MB | 1GB | 100Mbps |
| **CrowdSec Core** | 1 vCPU | 256MB | 500MB | 10Mbps |
| **Reverse Proxy** | 1 vCPU | 256MB | 100MB | 1Gbps |

### Recommended System Requirements
| Component | CPU | Memory | Storage | Network |
|-----------|-----|--------|---------|---------|
| **CrowdSec Manager** | 2 vCPU | 2GB | 10GB | 1Gbps |
| **CrowdSec Core** | 2 vCPU | 1GB | 5GB | 100Mbps |
| **Reverse Proxy** | 2 vCPU | 1GB | 1GB | 1Gbps |

## Testing Matrix

### Automated Testing Coverage
| Proxy Type | Unit Tests | Integration Tests | E2E Tests | Property Tests |
|------------|------------|------------------|-----------|----------------|
| **Traefik** | ✅ | ✅ | ✅ | ✅ |
| **Nginx PM** | ✅ | ✅ | ✅ | ✅ |
| **Caddy** | ✅ | ✅ | ✅ | ✅ |
| **HAProxy** | ✅ | ✅ | ✅ | ✅ |
| **Zoraxy** | ✅ | ✅ | ⚠️ | ✅ |
| **Standalone** | ✅ | ✅ | ✅ | ✅ |

## Support Lifecycle

### Version Support Policy
| Version | Release Date | End of Support | Security Updates |
|---------|--------------|----------------|------------------|
| **v2.0.x** | 2024-12 | 2026-12 | ✅ Active |
| **v1.x** | 2024-06 | 2025-06 | ✅ Security Only |
| **v0.x** | 2024-01 | 2024-12 | ❌ End of Life |

### Proxy Support Policy
- **Stable Proxies**: Long-term support with regular updates
- **Experimental Proxies**: Best-effort support, may be deprecated
- **Legacy Versions**: Security updates only, feature development stopped

---

**Note**: This compatibility matrix is updated with each release. Always check the latest version for current compatibility information.