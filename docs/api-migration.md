# API Migration Guide

This document describes deprecated API endpoints, their replacements, and the sunset timeline.

## Deprecated Endpoints

All deprecated endpoints return standard HTTP deprecation headers:

| Header         | Value                                      |
| -------------- | ------------------------------------------ |
| `Deprecation`  | `true`                                     |
| `Sunset`       | `2026-08-01`                               |
| `Link`         | `<replacement>; rel="successor-version"`   |

### Whitelist

| Deprecated                        | Replacement                 | Notes                                |
| --------------------------------- | --------------------------- | ------------------------------------ |
| `POST /api/whitelist/traefik`     | `POST /api/whitelist/proxy` | Generic proxy whitelist endpoint     |

### Logs

| Deprecated                         | Replacement                    | Notes                              |
| ---------------------------------- | ------------------------------ | ---------------------------------- |
| `GET /api/logs/traefik`            | `GET /api/logs/proxy`          | Generic proxy log retrieval        |
| `GET /api/logs/traefik/advanced`   | `GET /api/logs/proxy/analyze`  | Generic proxy log analysis         |

### Traefik Configuration

| Deprecated                          | Replacement                     | Notes                            |
| ----------------------------------- | ------------------------------- | -------------------------------- |
| `GET /api/traefik/config`           | `GET /api/proxy/current`        | Use proxy-generic endpoint       |
| `GET /api/traefik/config-path`      | `GET /api/proxy/current`        | Use proxy-generic endpoint       |
| `POST /api/traefik/config-path`     | `POST /api/proxy/configure`     | Use proxy-generic endpoint       |

## Timeline

- **Now**: Deprecated endpoints continue to work with deprecation headers.
- **2026-08-01**: Deprecated endpoints will be removed. Clients must migrate to replacement endpoints.

## Migration Steps

### Backend Consumers

Replace API calls to deprecated paths with their replacement equivalents. The request/response shapes remain compatible.

### Frontend

The frontend has already been updated to use proxy-generic endpoints. The deprecated `traefikAPI` client in `web/src/lib/api/traefik.ts` is retained but marked with `@deprecated` JSDoc annotations.

## New Proxy-Generic Endpoints

| Endpoint                             | Method | Description                                  |
| ------------------------------------ | ------ | -------------------------------------------- |
| `GET /api/proxy/types`               | GET    | List all available proxy types               |
| `GET /api/proxy/current`             | GET    | Get current proxy configuration and status   |
| `GET /api/proxy/features`            | GET    | Get supported features for current proxy     |
| `POST /api/proxy/configure`          | POST   | Update proxy configuration                   |
| `GET /api/proxy/health`              | GET    | Check proxy health                           |
| `GET /api/proxy/bouncer/status`      | GET    | Get bouncer integration status               |
| `POST /api/proxy/bouncer/validate`   | POST   | Validate bouncer configuration               |
