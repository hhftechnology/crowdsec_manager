# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Require `API_TOKEN` on every `/api` route, including the terminal WebSocket, and reject browser requests from other origins.
- Build the server with Go 1.27.3.
- Update `golang.org/x/net` to v0.62.0, `golang.org/x/crypto` to v0.58.0, and `golang.org/x/text` to v0.43.0.
- Pin the runtime image to Alpine 3.23 so `brotli-libs` is 1.2.1-r0 (CVE-2026-111497).
- Update the web UI to axios 1.20.0, with form-data 4.0.6 and follow-redirects 1.16.2.
- Update react-router-dom to 6.30.6.
- Update the web dev toolchain to vite 8.1.6 and esbuild 0.28.1, and patch postcss 8.5.18, nanoid 3.3.18, and source-map-js 1.2.2.

### Added

- Pull requests into `dev-fix` must use a conventional commit title and change `CHANGELOG.md`.
