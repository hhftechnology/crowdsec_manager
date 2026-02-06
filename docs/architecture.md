# CrowdSec Manager Architecture

## Overview

CrowdSec Manager is a centralized management dashboard for CrowdSec instances with a Go backend (Gin) and React frontend (Vite).

## Backend Package Structure

```
cmd/server/
  main.go                        Entry point, config, graceful shutdown

internal/
  api/
    deps.go                      Dependencies struct (shared across all routes)
    routes.go                    RegisterAll() thin orchestrator
    routes_health.go             Health & diagnostics endpoints
    routes_ip.go                 IP ban/unban/check endpoints
    routes_whitelist.go          CrowdSec + proxy whitelist management
    routes_allowlist.go          CrowdSec allowlist CRUD
    routes_scenarios.go          Custom scenario management
    routes_captcha.go            Captcha setup and status
    routes_logs.go               Log viewing and analysis
    routes_backup.go             Backup/restore operations
    routes_update.go             Docker image update management
    routes_services.go           Docker service management
    routes_crowdsec.go           CrowdSec bouncers, decisions, metrics, enrollment
    routes_traefik.go            Legacy Traefik endpoints (all deprecated)
    routes_config.go             Settings and file content endpoints
    routes_notifications.go      Discord webhook notification endpoints
    routes_cron.go               Cron job management
    routes_profiles.go           Profiles.yaml management
    routes_proxy.go              Proxy info, features, health, bouncer status
    routes_addons.go             Add-on management (Pangolin/Gerbil)
    routes_validation.go         Environment and path validation

    dto/
      response.go                Standardized API response envelope
      response_test.go           DTO tests

    middleware/
      feature_guard.go           RequireFeature() - blocks unsupported features
      deprecated.go              Deprecated() - adds deprecation headers
      feature_guard_test.go
      deprecated_test.go

    handlers/                    Handler implementations (one file per domain)
      health.go, ip.go, whitelist.go, ...

  proxy/
    proxy.go                     ProxyAdapter interface + feature manager interfaces
    factory.go                   Global adapter registry + ProxyManager
    features.go                  FeatureSet, ProxyFeatureMatrix
    helpers.go                   Nil-safe RequireWhitelist/Captcha/Logs/Bouncer
    config_resolver.go           ResolveConfig(), ResolveProxyType()
    adapters/                    Per-proxy implementations
      traefik/, nginx/, caddy/, haproxy/, zoraxy/, standalone/

  config/                        Configuration loading and validation
  database/                      SQLite connection and migrations
  docker/                        Docker API client
  backup/                        Backup manager
  cron/                          Cron scheduler
  compose/                       Docker Compose management
  logger/                        Structured logging
  models/                        Shared data models
  validation/                    Input validation utilities
```

## Frontend Structure

```
web/src/
  lib/
    api/
      client.ts                  Shared axios instance + types
      health.ts                  Health API client
      ip.ts                      IP management client
      whitelist.ts               Whitelist client
      allowlist.ts               Allowlist client
      scenarios.ts               Scenarios client
      captcha.ts                 Captcha client
      logs.ts                    Logs client
      backup.ts                  Backup client
      update.ts                  Update client
      cron.ts                    Cron client
      services.ts                Services client
      crowdsec.ts                CrowdSec client
      notifications.ts           Notifications client
      traefik.ts                 Legacy Traefik client (deprecated)
      proxy.ts                   Proxy management client
      validation.ts              Validation client
      addons.ts                  Add-ons client
      index.ts                   Barrel re-exports for backward compat
    api.ts                       Re-exports from api/ (backward compat)

  contexts/
    ProxyContext.tsx              Canonical source for proxy type & features
    DeploymentContext.tsx         Container detection, consumes ProxyContext
```

## Key Design Decisions

### Dependencies Struct

All handler dependencies are bundled in `api.Dependencies` to avoid parameter sprawl:

```go
deps := &api.Dependencies{
    Docker:        dockerClient,
    DB:            db,
    Config:        cfg,
    ProxyAdapter:  proxyAdapter,
    ProxyManager:  proxyManager,
    BackupManager: backupManager,
    CronScheduler: cronScheduler,
}
api.RegisterAll(apiGroup, deps)
```

### Standardized API Responses

All endpoints return `dto.Response` shape:

```json
{
  "success": true|false,
  "message": "optional message",
  "data": { ... },
  "error": "error message if success=false"
}
```

### Feature Guard Middleware

Routes that require specific proxy features use `RequireFeature` middleware:

```go
captchaGroup.Use(middleware.RequireFeature(adapter, proxy.FeatureCaptcha))
```

### Deprecation Middleware

Legacy Traefik-specific endpoints use `Deprecated` middleware that sets HTTP headers:

```go
whitelist.POST("/traefik",
    middleware.Deprecated("/api/whitelist/proxy"),
    handlers.AddToTraefikWhitelist(...),
)
```

## Multi-Proxy Support

### Supported Proxies and Features

| Feature   | Traefik | Nginx | Caddy | HAProxy | Zoraxy | Standalone |
| --------- | ------- | ----- | ----- | ------- | ------ | ---------- |
| whitelist | Yes     | -     | -     | -       | -      | -          |
| captcha   | Yes     | -     | -     | -       | -      | -          |
| logs      | Yes     | Yes   | -     | -       | -      | -          |
| bouncer   | Yes     | Yes   | Yes   | Yes     | -      | -          |
| health    | Yes     | Yes   | Yes   | Yes     | Yes    | Yes        |
| appsec    | Yes     | -     | -     | -       | -      | -          |

### Adding a New Proxy Type

1. Create adapter in `internal/proxy/adapters/<name>/adapter.go`
2. Implement the `ProxyAdapter` interface
3. Register via `init()` function using `proxy.RegisterAdapter()`
4. Add entry to `ProxyFeatureMatrix` in `internal/proxy/features.go`
5. Update `proxy.GetAllProxyTypes()` and `proxy.ValidateProxyType()`
6. Update frontend `PROXY_TYPES` in `web/src/lib/proxy-types.ts`

### Adding a New API Domain

1. Create `internal/api/routes_<domain>.go` with a `register<Domain>Routes()` function
2. Create handler functions in `internal/api/handlers/<domain>.go`
3. Add call to `register<Domain>Routes()` in `routes.go:RegisterAll()`
4. Create frontend client in `web/src/lib/api/<domain>.ts`
5. Re-export from `web/src/lib/api/index.ts`
