# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-27

### Added

- `bcrypt` password hash provider for Keycloak 26 (built against 26.8.1).
- Verification of `$2a$`, `$2b$` and `$2y$` hashes with any cost factor from 4 to 31.
- bcrypt hashing of new passwords (`$2a$`) with a configurable cost (`--spi-password-hashing--bcrypt--cost`, default 12), used only when a realm sets `hashAlgorithm(bcrypt)`.
- Single drop-in jar with the bcrypt library shaded and relocated.
- Import examples: realm JSON, Admin REST API payload and a `curl` script.
- Unit tests against Spring Security, Apache `htpasswd` and PHP hashes; Testcontainers integration test behind the `it` profile.
- GitHub Actions CI.
