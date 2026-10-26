# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.13.2](https://github.com/Authkestra/authkestra/compare/authkestra-axum-v0.13.1...authkestra-axum-v0.13.2) - 2026-10-26

### Added

- *(mcp)* add authkestra-mcp crate, Axum/Actix adapters, and AI agent security ([#415](https://github.com/Authkestra/authkestra/pull/415))

## [0.13.1](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.13.0...authkestra-axum-v0.13.1) - 2026-09-26

### Other

- give every published crate its own crates.io keywords/categories ([#412](https://github.com/marcjazz/authkestra/pull/412))

## [0.13.0](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.12.0...authkestra-axum-v0.13.0) - 2026-09-23

### Other

- Bring the READMEs up to v0.13 ([#409](https://github.com/marcjazz/authkestra/pull/409))

## [0.11.0](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.10.2...authkestra-axum-v0.11.0) - 2026-09-14

### Added

- *(op)* [**breaking**] honour max_age / prompt=login re-authentication at /authorize ([#383](https://github.com/marcjazz/authkestra/pull/383))

### Fixed

- *(engine)* de-feature token — always compile token machinery in ([#377](https://github.com/marcjazz/authkestra/pull/377))
- *(engine)* [**breaking**] remove authkestra-engine's no-op `session` feature ([#375](https://github.com/marcjazz/authkestra/pull/375))

## [0.10.2](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.10.1...authkestra-axum-v0.10.2) - 2026-09-14

### Fixed

- *(actix, axum)* no-op / missing feature-gate audit across the workspace ([#373](https://github.com/marcjazz/authkestra/pull/373))

## [0.9.4](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.9.3...authkestra-axum-v0.9.4) - 2026-09-08

### Other

- *(actix)* share one callback helper instead of two copies of the CSRF check ([#361](https://github.com/marcjazz/authkestra/pull/361))

## [0.9.3](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.9.2...authkestra-axum-v0.9.3) - 2026-09-07

### Added

- instrument the token-validation path, and fix flaky log-capture tests ([#358](https://github.com/marcjazz/authkestra/pull/358))
- *(adapters)* instrument the OAuth login, callback and logout handlers ([#355](https://github.com/marcjazz/authkestra/pull/355))

### Fixed

- *(macros)* anchor derive output so the state derives work through the facade ([#344](https://github.com/marcjazz/authkestra/pull/344))

### Other

- *(adapters)* cover the OpenID Provider handlers in both axum and actix ([#346](https://github.com/marcjazz/authkestra/pull/346))

## [0.9.0](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.8.1...authkestra-axum-v0.9.0) - 2026-09-05

### Fixed

- *(axum)* [**breaking**] make AxumError non_exhaustive ([#331](https://github.com/marcjazz/authkestra/pull/331))
- *(adapters)* [**breaking**] return 404 for an unknown OAuth provider, and stop the body being sniffed ([#323](https://github.com/marcjazz/authkestra/pull/323))

## [0.8.0](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.7.2...authkestra-axum-v0.8.0) - 2026-09-03

### Other

- Merge next into main: storage rework, DPoP, PKCE/scope hardening ([#300](https://github.com/marcjazz/authkestra/pull/300))

## [0.7.2](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.7.1...authkestra-axum-v0.7.2) - 2026-09-03

### Other

- refresh engine guides, provider docs and the book against current code ([#305](https://github.com/marcjazz/authkestra/pull/305))

## [0.7.0](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.6.3...authkestra-axum-v0.7.0) - 2026-08-31

### Other

- add coverage for auth strategies and flow orchestration ([#297](https://github.com/marcjazz/authkestra/pull/297)) ([#298](https://github.com/marcjazz/authkestra/pull/298))
- Merge next into main (DPoP, migrations, and fixes) ([#292](https://github.com/marcjazz/authkestra/pull/292))

## [0.6.2](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.6.1...authkestra-axum-v0.6.2) - 2026-08-28

### Other

- correct API drift across README, crate docs, website and book ([#269](https://github.com/marcjazz/authkestra/pull/269))

## [0.6.0](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.5.5...authkestra-axum-v0.6.0) - 2026-08-27

### Other

- massive sweep to add non_exhaustive to all public structs ([#259](https://github.com/marcjazz/authkestra/pull/259))

## [0.5.4](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.5.3...authkestra-axum-v0.5.4) - 2026-08-24

### Added

- *(op)* RFC 8705 certificate-bound access tokens for client_credentials ([#231](https://github.com/marcjazz/authkestra/pull/231))

## [0.5.3](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.5.2...authkestra-axum-v0.5.3) - 2026-08-24

### Other

- *(axum,actix)* add E2E integration tests for engine adapters ([#232](https://github.com/marcjazz/authkestra/pull/232))

## [0.5.2](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.5.1...authkestra-axum-v0.5.2) - 2026-08-24

### Fixed

- *(ci)* unblock lint and deny after Rust 1.98 and RUSTSEC-2026-0258 drift ([#227](https://github.com/marcjazz/authkestra/pull/227))

## [0.3.4](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.3.3...authkestra-axum-v0.3.4) - 2026-08-05

### Other

- updated the following local packages: authkestra-engine, authkestra-resource, authkestra-op

## [0.3.3](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.3.2...authkestra-axum-v0.3.3) - 2026-08-02

### Fixed

- *(deps)* let consumers choose the TLS backend instead of forcing aws-lc-rs ([#179](https://github.com/marcjazz/authkestra/pull/179))

## [0.3.2](https://github.com/marcjazz/authkestra/compare/authkestra-axum-v0.3.1...authkestra-axum-v0.3.2) - 2026-08-01

### Added

- upgrade jsonwebtoken to v11.x and resolve docs/promises ([#175](https://github.com/marcjazz/authkestra/pull/175)) ([#176](https://github.com/marcjazz/authkestra/pull/176))

### Other

- clean up scratch dir and bump documentation versions to 0.3.1 ([#173](https://github.com/marcjazz/authkestra/pull/173))

## [0.3.1](https://github.com/marcjazz/authkestra/compare/v0.2.4...v0.3.1) - 2026-07-31

### Fixed

- move examples to root crate to permanently resolve cyclic publish failures ([#168](https://github.com/marcjazz/authkestra/pull/168))
- remove circular dev-dependencies from axum and actix adapters ([#159](https://github.com/marcjazz/authkestra/pull/159))

### Other

- release v0.3.0 ([#166](https://github.com/marcjazz/authkestra/pull/166))
- rollback workspace version to 0.2.4 ([#165](https://github.com/marcjazz/authkestra/pull/165))
- merge develop into main (conflict free) ([#155](https://github.com/marcjazz/authkestra/pull/155))
- Release/v0.2.5 ([#149](https://github.com/marcjazz/authkestra/pull/149))

## [0.3.0](https://github.com/marcjazz/authkestra/compare/v0.2.4...v0.3.0) - 2026-07-31

### Fixed

- remove circular dev-dependencies from axum and actix adapters ([#159](https://github.com/marcjazz/authkestra/pull/159))

### Other

- rollback workspace version to 0.2.4 ([#165](https://github.com/marcjazz/authkestra/pull/165))
- merge develop into main (conflict free) ([#155](https://github.com/marcjazz/authkestra/pull/155))
- Release/v0.2.5 ([#149](https://github.com/marcjazz/authkestra/pull/149))
