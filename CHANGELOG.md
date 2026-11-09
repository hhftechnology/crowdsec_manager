# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pull requests into `dev-fix` need at least one entry under Unreleased,
unless the pull request has the `skip-changelog` label.

## [Unreleased]

### Security

- Pin the runtime image to Alpine 3.23 so `brotli-libs` is 1.2.1-r0 (CVE-2026-111497).
- Update axios to 1.20.0, with form-data 4.0.6 and follow-redirects 1.16.2.
- Update react-router-dom to 6.30.6.
- Update the web dev toolchain to vite 8.1.6 and esbuild 0.28.1. postcss 8.5.23, nanoid 3.3.18, and source-map-js 1.2.2 move with that toolchain.
- Update proxy-addr to 2.0.8, undici to 7.30.1, and `@modelcontextprotocol/sdk` to 1.32.0.
- Update fast-uri to 3.1.7, brace-expansion to 1.1.20 and 5.0.11, js-yaml to 4.3.2, hono to 4.12.25, ip-address to 10.3.1, and browserslist to 4.28.7.

### Added

- Pull requests into `dev-fix` fail when `CHANGELOG.md` has no Unreleased entry, unless they carry the `skip-changelog` label.
- Tag pushes draft a GitHub release from this changelog.
- Add the MIT `LICENSE` file named by the README.
