# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.15.0](https://github.com/Authkestra/authkestra/compare/authkestra-mcp-v0.14.0...authkestra-mcp-v0.15.0) - 2026-11-07

### Fixed

- *(sec)* policy, MCP, devsig, and SSF security hardening (Cluster 6) ([#434](https://github.com/Authkestra/authkestra/pull/434))
- *(telemetry)* redact credentials from tracing and prevent log injection ([#429](https://github.com/Authkestra/authkestra/pull/429))
- *(mcp)* prevent cross-identity token exposure in the vault ([#424](https://github.com/Authkestra/authkestra/pull/424))
- *(mcp)* prevent approval bypass through lossy JCS canonicalization ([#425](https://github.com/Authkestra/authkestra/pull/425))

## [0.13.3](https://github.com/Authkestra/authkestra/compare/authkestra-mcp-v0.13.2...authkestra-mcp-v0.13.3) - 2026-10-26

### Added

- *(policy,ssf)* wire CedarPolicyEngine and OpenID CAEP/SSF receiver into resource, mcp, axum, and actix ([#418](https://github.com/Authkestra/authkestra/pull/418))

## [0.13.2](https://github.com/Authkestra/authkestra/compare/authkestra-mcp-v0.13.1...authkestra-mcp-v0.13.2) - 2026-10-26

### Added

- *(mcp)* add authkestra-mcp crate, Axum/Actix adapters, and AI agent security ([#415](https://github.com/Authkestra/authkestra/pull/415))

### Fixed

- *(ci)* update zstd/actix-web in Cargo.lock and add authkestra-mcp to release-plz.toml ([#416](https://github.com/Authkestra/authkestra/pull/416))
