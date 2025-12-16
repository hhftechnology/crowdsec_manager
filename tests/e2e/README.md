# End-to-End Testing Suite

This directory contains comprehensive end-to-end tests for the CrowdSec Manager multi-proxy architecture. The test suite validates all aspects of the system including browser automation, proxy integration, migration scenarios, and performance testing.

## Test Categories

### 1. Browser Automation Tests (`browser_test.go`)
- **UI Workflows**: Complete user workflows for each proxy type
- **Navigation**: Proxy detection and adaptive navigation
- **Feature Availability**: Proxy-specific feature visibility
- **Responsive Design**: Mobile, tablet, and desktop layouts
- **Accessibility**: Keyboard navigation and ARIA compliance

### 2. Proxy Integration Tests (`proxy_integration_test.go`)
- **API Endpoints**: Core API functionality for each proxy type
- **Feature Testing**: Proxy-specific feature validation
- **Health Monitoring**: Comprehensive health checks
- **Configuration Management**: Proxy configuration APIs
- **Backward Compatibility**: Legacy API endpoint support

### 3. Migration Tests (`migration_test.go`)
- **Legacy Traefik Migration**: Automatic detection and migration
- **Environment Variables**: Legacy variable mapping
- **Database Migration**: Schema updates and data preservation
- **Configuration Backup**: Backup creation during migration
- **Functionality Preservation**: Legacy functionality continues working

### 4. Performance Tests (`performance_test.go`)
- **API Performance**: Load testing of API endpoints
- **Memory Usage**: Memory consumption monitoring
- **Concurrent Operations**: Multi-user scenario testing
- **Startup Performance**: Application startup time measurement

## Test Infrastructure

### Test Environment Setup (`setup.go`)
- **Docker Compose Management**: Single and separate deployment modes
- **Service Orchestration**: Automated service startup and health checking
- **File Management**: Test configuration and compose file generation
- **Cleanup**: Automatic resource cleanup after tests

### Test Runner (`runner.go`)
- **Configuration Management**: Flexible test configuration
- **Parallel Execution**: Concurrent test execution support
- **Category Filtering**: Run specific test categories
- **Report Generation**: Comprehensive test reporting

## Running Tests

### Prerequisites
- Docker and Docker Compose installed
- Go 1.23+ installed
- Chrome/Chromium for browser tests
- At least 4GB RAM available for containers

### Quick Start
```bash
# Run all tests
make -f Makefile.e2e test-e2e

# Run specific test categories
make -f Makefile.e2e test-browser
make -f Makefile.e2e test-integration
make -f Makefile.e2e test-migration
make -f Makefile.e2e test-performance

# Run tests for specific proxy types
make -f Makefile.e2e test-traefik
make -f Makefile.e2e test-nginx
make -f Makefile.e2e test-standalone

# Run smoke tests (quick validation)
make -f Makefile.e2e test-smoke
```

### Configuration Options

Environment variables can be used to configure test execution:

```bash
# Test execution settings
export E2E_TIMEOUT=30m          # Overall test timeout
export E2E_PARALLEL=true        # Run tests in parallel
export E2E_VERBOSE=true         # Verbose logging
export E2E_SKIP_CLEANUP=true    # Skip cleanup for debugging

# Browser settings
export E2E_HEADLESS=false       # Run browser tests visibly
export E2E_BROWSER_TIMEOUT=5m   # Browser operation timeout

# Performance settings
export E2E_LOAD_DURATION=60s    # Load test duration
export E2E_LOAD_CONCURRENCY=20  # Concurrent users

# Docker settings
export DOCKER_REGISTRY=myregistry.com
export IMAGE_TAG=latest
```

### Test Execution Examples

```bash
# Development testing with cleanup disabled
export E2E_SKIP_CLEANUP=true
export E2E_VERBOSE=true
make -f Makefile.e2e test-traefik

# CI/CD testing
make -f Makefile.e2e test-ci

# Performance benchmarking
make -f Makefile.e2e benchmark

# Continuous testing (watch mode)
make -f Makefile.e2e test-watch
```

## Test Structure

### Test Environment Lifecycle
1. **Setup**: Create temporary directories, generate compose files
2. **Start Services**: Launch containers with appropriate profiles
3. **Wait for Ready**: Health check all required services
4. **Execute Tests**: Run test scenarios
5. **Cleanup**: Stop containers and remove temporary files

### Proxy Type Coverage
- **Traefik**: Full feature testing (whitelist, captcha, logs, bouncer)
- **Nginx Proxy Manager**: Log parsing and bouncer integration
- **Caddy**: Bouncer integration and health monitoring
- **HAProxy**: SPOA bouncer integration
- **Zoraxy**: Basic health monitoring (experimental)
- **Standalone**: CrowdSec-only functionality

### Compose Mode Coverage
- **Single Mode**: Profile-based service management
- **Separate Mode**: Multiple compose file deployment

## Test Data and Fixtures

### Generated Test Files
- Docker Compose configurations for each proxy type
- Environment files with appropriate variables
- Mock configuration files for testing
- Sample databases for migration testing

### Test Scenarios
- Fresh installations for each proxy type
- Legacy Traefik installations requiring migration
- Various environment variable configurations
- Different compose deployment strategies

## Debugging Tests

### Verbose Logging
```bash
export E2E_VERBOSE=true
make -f Makefile.e2e test-traefik
```

### Skip Cleanup for Investigation
```bash
export E2E_SKIP_CLEANUP=true
make -f Makefile.e2e test-integration
# Containers and files remain for manual inspection
```

### Browser Tests in Visible Mode
```bash
export E2E_HEADLESS=false
make -f Makefile.e2e test-browser
```

### Manual Environment Inspection
```bash
# Start test environment manually
make -f Makefile.e2e compose-up-traefik

# Access services
curl http://localhost:8080/api/health
curl http://localhost:8081  # Traefik dashboard

# Stop when done
make -f Makefile.e2e compose-down
```

## Test Reports and Artifacts

### Generated Artifacts
- `tests/logs/`: Container logs and test execution logs
- `tests/artifacts/`: Screenshots, performance reports, coverage data
- `tests/reports/`: Test execution summaries and reports
- `coverage.html`: Test coverage report

### Performance Metrics
- API response times and throughput
- Memory usage patterns
- Container startup times
- Concurrent operation success rates

## Continuous Integration

### CI Configuration
The test suite is designed for CI/CD environments:

```yaml
# Example GitHub Actions configuration
- name: Run E2E Tests
  run: |
    export E2E_PARALLEL=false
    export E2E_VERBOSE=true
    make -f Makefile.e2e test-ci
```

### Test Parallelization
- Browser tests can run in parallel across proxy types
- Integration tests support parallel execution
- Migration tests run sequentially (database operations)
- Performance tests run sequentially (accurate measurements)

## Extending Tests

### Adding New Proxy Types
1. Add proxy type to `ProxyTypeGenerator` in test files
2. Update `expectedFeatures` maps with supported features
3. Add proxy-specific test methods
4. Update compose file generation in `setup.go`

### Adding New Test Scenarios
1. Create new test functions following naming conventions
2. Use existing test infrastructure (`SetupTestEnvironment`)
3. Add configuration options to `TestConfig` if needed
4. Update Makefile targets for new test categories

### Custom Test Configuration
```go
config := &TestConfig{
    ProxyTypes: []string{"traefik", "nginx"},
    TestCategories: []string{"integration"},
    LoadTestDuration: 60 * time.Second,
    // ... other settings
}
runner := NewTestRunner(config)
```

## Troubleshooting

### Common Issues

**Docker Permission Errors**
```bash
# Add user to docker group
sudo usermod -aG docker $USER
# Restart shell or logout/login
```

**Port Conflicts**
```bash
# Check for conflicting services
sudo netstat -tlnp | grep :8080
# Stop conflicting services before running tests
```

**Memory Issues**
```bash
# Increase Docker memory limit
# Check available memory: free -h
# Ensure at least 4GB available
```

**Browser Test Failures**
```bash
# Install Chrome/Chromium
sudo apt-get install chromium-browser
# Or use headless mode
export E2E_HEADLESS=true
```

### Log Analysis
```bash
# View container logs
docker logs crowdsec-manager

# View test execution logs
tail -f tests/logs/test-execution.log

# Check service health
docker-compose ps
```

This comprehensive test suite ensures the multi-proxy architecture works correctly across all supported proxy types and deployment modes, providing confidence in the system's reliability and performance.